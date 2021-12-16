import pathlib
import logging

from docker.models.containers import Container

from vantage6.node.util import logger_name

log = logging.getLogger(logger_name(__name__))


def running_in_docker() -> bool:
    """Return True if this code is executed within a Docker container."""
    return pathlib.Path('/.dockerenv').exists()


def remove_container(container: Container, kill=False) -> None:
    """
    Removes a docker container

    Parameters
    ----------
    container: Container
        The container that should be removed
    kill: bool
        Whether or not container should be killed before it is removed
    """
    if kill:
        try:
            container.kill()
        except Exception as e:
            pass  # allow failure here, maybe container had already exited
    try:
        container.remove()
    except Exception as e:
        log.error(f"Failed to remove container {container.name}")
        log.debug(e)


def get_network_ip(container, network_name) -> str:
    """
    Get address of a container in a network

    Parameters
    ----------
    container: Container
        Docker container whose IP address should be obtained

    Returns
    -------
    str
        IP address of a container in isolated network
    """
    container.reload()
    try:
        return container.attrs['NetworkSettings']['Networks'][network_name][
            'IPAddress']
    except Exception as e:
        log.warn(f"Could not find container {container.name} in network "
                 f"{network_name}")
        return None
