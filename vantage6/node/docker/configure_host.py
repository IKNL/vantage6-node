import json
import logging

from typing import List, Union, Dict
from docker.client import DockerClient
from docker.models.containers import Container

from vantage6.node.util import logger_name
from vantage6.node.globals import NETWORK_CONFIG_IMAGE
from vantage6.node.docker.utils import get_network_ip, remove_container
from vantage6.node.docker.network_manager import IsolatedNetworkManager

log = logging.getLogger(logger_name(__name__))


def find_isolated_bridge(
        docker_client: DockerClient,
        isolated_network_mgr: IsolatedNetworkManager,
        isolated_network_container: Container = None) -> str:
    """
    Retrieve the linked network interface in the host namespace for
    network interface eth0 in the container namespace.

    Parameters
    ----------
    docker_client: DockerClient
        Client to call docker CLI
    isolated_network: Network
        The Docker isolated network
    isolated_network_container: Container | None
        Container in the isolated network. Temporary container is generated if
        this is None

    Returns
    -------
    string
        The name of the network interface in the host namespace
    """
    using_temp_container = False
    if not isolated_network_container:
        # create a temporary container in the isolated network if none is
        # available
        isolated_network_container = docker_client.containers.run(
            command='sleep infinity',
            image=NETWORK_CONFIG_IMAGE,
            detach=True,
            cap_add=['NET_ADMIN', 'SYSLOG'],
            devices=['/dev/net/tun'],
        )
        # attach vpnclient to isolated network. NB: this cannot be replaced by
        # doing network=... in the running of the container above!
        isolated_network_mgr.connect(
            container_name=isolated_network_container.name,
            aliases=[isolated_network_container.name]
        )
        using_temp_container = True

    # Get the isolated network interface
    isolated_interface = _get_interface(
        container=isolated_network_container,
        network_name=isolated_network_mgr.network_name
    )

    # extract the isolated network link index
    if isolated_interface:
        link_index = _get_link_index(isolated_interface)
    else:
        if using_temp_container:
            remove_container(isolated_network_container, kill=True)
        return None  # cannot setup host rules if link is not found

    # Get network config from host namespace
    host_interfaces = docker_client.containers.run(
        image=NETWORK_CONFIG_IMAGE,
        network='host',
        command=['ip', '--json', 'addr'],
        remove=True
    )
    host_interfaces = json.loads(host_interfaces)

    linked_interface = _get_if(host_interfaces, link_index)
    bridge_interface = linked_interface['master']
    if using_temp_container:
        remove_container(isolated_network_container, kill=True)
    return bridge_interface


def configure_host_network(docker_client: DockerClient, isolated_bridge: str,
                           subnet: str) -> None:
    """
    By default the internal bridge networks are configured to prohibit
    packet forwarding between networks. Create an exception to this rule
    for forwarding traffic between the bridge and vpn network.

    Parameters
    ----------
    docker_client: DockerClient
        Client to call docker CLI
    vpn_subnet: string
        Subnet of allowed VPN IP addresses
    isolated_bridge: string
        Name of the network interface in the host namespace
    """
    log.debug("Configuring host network exceptions for VPN")
    # The following command inserts rules that traffic from the VPN subnet
    # will be accepted into the isolated network
    command = (
        'sh -c "'
        f'iptables -I DOCKER-USER 1 -d {subnet} -i {isolated_bridge} '
        '-j ACCEPT; '
        f'iptables -I DOCKER-USER 1 -s {subnet} -o {isolated_bridge} '
        '-j ACCEPT; '
        '"'
    )

    docker_client.containers.run(
        image=NETWORK_CONFIG_IMAGE,
        network='host',
        cap_add='NET_ADMIN',
        command=command,
        remove=True,
    )


def remove_host_exceptions(docker_client: DockerClient,
                           n_whitelists_to_remove: int):
    """
    Clean up host network changes from whitelists. For each whitelisted IP, we
    have to remove two rules (one for incoming, one for outgoing)
    """
    if n_whitelists_to_remove == 0:
        return
    command = 'sh -c "'
    # remove two rules per whitelist (1 incoming, 1 outgoing)
    for _ in range(n_whitelists_to_remove):
        command += 'iptables -D DOCKER-USER 1; iptables -D DOCKER-USER 1;'
    command += '"'
    docker_client.containers.run(
        image=NETWORK_CONFIG_IMAGE,
        network='host',
        cap_add='NET_ADMIN',
        command=command,
        remove=True,
    )


def _get_interface(container: Container,
                   network_name: str) -> Union[Dict, None]:
    """
    Get the isolated network interface

    Get all network descriptions from a container in the isolated network and
    match the isolated
    network's interface by VPN ip address: this should be the same in the
    VPN container's attributes and in the network interface

    Parameters
    ----------
    container: Container
        A docker container in the isolated network

    Returns
    -------
    Dict or None
        The interface of the isolated network. None if not found
    """
    isolated_interface = None
    _, interfaces = container.exec_run("ip --json addr")
    interfaces = json.loads(interfaces)
    ip_isolated_netw = get_network_ip(container, network_name)
    for ip_interface in interfaces:
        if _is_isolated_interface(ip_interface, ip_isolated_netw):
            isolated_interface = ip_interface
    return isolated_interface


def _is_isolated_interface(ip_interface: Dict, vpn_ip_isolated_netw: str):
    """
    Return True if a network interface is the isolated network
    interface. Identify this based on the IP address of the VPN client in
    the isolated network

    Parameters
    ----------
    ip_interface: dict
        IP interface obtained by executing `ip --json addr` command
    vpn_ip_isolated_netw: str
        IP address of VPN container in isolated network

    Returns
    -------
    boolean:
        True if this is the interface describing the isolated network
    """
    # check if attributes exist in json: if not then it is not the right
    # interface
    if ('addr_info' in ip_interface and len(ip_interface['addr_info']) and
            'local' in ip_interface['addr_info'][0]):
        # Right attributes are present: check if IP addresses match
        return vpn_ip_isolated_netw == \
            ip_interface['addr_info'][0]['local']
    else:
        return False


def _get_if(interfaces, index) -> Union[Dict, None]:
    """ Get interface configuration based on interface index """
    for interface in interfaces:
        if int(interface['ifindex']) == index:
            return interface
    return None


def _get_link_index(if_json: Union[Dict, List]) -> int:
    if isinstance(if_json, list):
        if_json = if_json[-1]
    return int(if_json['link_index'])
