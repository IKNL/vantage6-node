""" Server IO

This module is basically a high level interface to the central server.

The module contains three communication classes: 1) The
NodeClient provides an interface from the Node to the central
server, 2) The UserClient provides an interface for users/
researchers and finally 3) The ContainerClient which provides
an interface for algorithms to the central server (this is mainly used
by master containers).
"""
import logging
import requests
import time
import jwt
import datetime
import typing

# from vantage6.node.encryption import Cryptor, NoCryptor
from vantage6.client import ClientBase
from vantage6.node.util import (
    bytes_to_base64s,
    base64s_to_bytes
)
from vantage6.client import WhoAmI

module_name = __name__.split('.')[1]

class ContainerClient(ClientBase):
    """ Container interface to the local proxy server (central server).

        A algorithm container (should) never communicate directly to the
        central server. Therefore the algorithm container has no
        internet connection. The algorithm can, however, talk to a local
        proxy server which has interface to the central server. This way
        we make sure that the algorithm container does not share stuff
        with others, and we also can encrypt the results for a specific
        receiver. Thus this not a interface to the central server but to
        the local proxy server. However the interface is identical thus
        we are happy that we can ignore this detail.
    """

    def __init__(self, token:str, *args, **kwargs):
        """ All permissions of the container are derived from the
            token.

            :param token: JWT (container) token, generated by the node
                the algorithm container runs on
        """
        super().__init__(*args, **kwargs)

        # obtain the identity from the token
        container_identity = jwt.decode(token, verify=False)['identity']
        self.image =  container_identity.get("image")
        self.host_node_id = container_identity.get("node_id")
        self.collaboration_id = container_identity.get("collaboration_id")
        self.log.info(
            f"Container in collaboration_id={self.collaboration_id} \n"
            f"Key created by node_id {self.host_node_id} \n"
            f"Can only use image={self.image}"
        )

        self._access_token = token
        self.log.debug(f"Access token={self._access_token}")

    def authenticate(self):
        """ Containers obtain their key via their host Node."""
        return

    def refresh_token(self):
        """ Containers cannot refresh their token.

            TODO we might want to notify node/server about this...
            TODO make a more usefull exception
        """
        raise Exception("Containers cannot refresh!")

    def get_results(self, task_id: int):
        """ Obtain results from a specific task at the server

            Containers are allowed to obtain the results of their
            children (having the same run_id at the server). The
            permissions are checked at te central server.

            :param task_id: id of the task from which you want to obtain
                the results
        """
        return self.request(
            f"task/{task_id}/result"
        )

    def create_new_task(self, input_, organization_ids=[]):
        """ Create a new (child) task at the central server.

            Containers are allowed to create child tasks (having the
            same run_id) at the central server. The docker image must
            be the same as the docker image of this container self.

            :param input_: input to the task
            :param organization_ids: organization ids which need to
                execute this task
        """
        self.log.debug(f"create new task for {organization_ids}")
        return self.post_task(
            name="subtask",
            description=f"task from container on node_id={self.host_node_id}",
            collaboration_id=self.collaboration_id,
            organization_ids=organization_ids,
            input_=input_,
            image=self.image
        )

    def get_organizations_in_my_collaboration(self):
        """ Obtain all organization in the collaboration.

            The container runs in a Node which is part of a single
            collaboration. This method retrieves all organization data
            that are within that collaboration. This can be used to
            target specific organizations in a collaboration.
        """
        organizations = self.request(
            f"collaboration/{self.collaboration_id}/organization")
        return organizations

    def post_task(self, name:str, image:str, collaboration_id:int,
        input_:str='', description='', organization_ids:list=[]) -> dict:
        """ Post a new task at the central server.

            ! To create a new task from the algorithm container you
            should use the `create_new_task` function !

            Creating a task from a container does need to be encrypted.
            This is done because the container should never have access
            to the private key of this organization. The encryption
            takes place in the local proxy server to which the algorithm
            communicates (indirectly to the central server). Therefore
            we needed to overload the post_task function.

            :param name: human-readable name
            :param image: docker image name of the task
            :param collaboration_id: id of the collaboration in which
                the task should run
            :param input_: input to the task
            :param description: human-readable description
            :param organization_ids: ids of the organizations where this
                task should run
        """
        self.log.debug("post task without encryption (is handled by proxy)")
        organization_json_list = []
        for org_id in organization_ids:
            organization_json_list.append(
                {
                    "id": org_id,
                    "input": input_
                }
            )

        return self.request('task', method='post', json={
            "name": name,
            "image": image,
            "collaboration_id": collaboration_id,
            "input": input_,
            "description": description,
            "organizations": organization_json_list
        })


class NodeClient(ClientBase):
    """ Node interface to the central server."""

    def __init__(self, *args, **kwargs):
        """ A node is always for a single collaboration."""
        super().__init__(*args, **kwargs)

        # FIXME: It seems the following attributes overlap with self.whoami?
        self.id = None
        # self.name = None
        self.collaboration_id = None
        self.whoami = None

    def authenticate(self, api_key: str):
        """ Nodes authentication at the central server.

            It also identifies itself by retrieving the collaboration
            and organization to which this node belongs. The server
            returns a JWT-token that is used in all succeeding requests.

            :param api_key: api-key used to authenticate to the central
                server
        """
        super().authenticate({"api_key": api_key}, path="token/node")

        # obtain the server authenticatable id
        id_ = jwt.decode(self.token, verify=False)['identity']

        # get info on how the server sees me
        node = self.request(f"node/{id_}")

        name = node.get("name")
        self.collaboration_id = node.get("collaboration").get("id")

        organization_id = node.get("organization").get("id")
        organization = self.request(f"organization/{organization_id}")
        organization_name = organization.get("name")

        self.whoami = WhoAmI(
            type_="node",
            id_=id_,
            name=name,
            organization_id=organization_id,
            organization_name=organization_name
        )

    def request_token_for_container(self, task_id: int, image: str):
        """ Request a container-token at the central server.

            This token is used by algorithm containers that run on this
            node. These algorithms can then post tasks and retrieve
            child-results (usually refered to as a master container).
            The server performs a few checks (e.g. if the task you
            request the key for is still open) before handing out this
            token.

            :param task_id: id from the task, which is going to use this
                container-token (a task results in a algorithm-
                container at the node)
            :param image: image-name of the task
        """
        self.log.debug(
            f"requesting container token for task_id={task_id} "
            f"and image={image}"
        )
        return self.request('/token/container', method="post", json={
            "task_id": task_id,
            "image": image
        })

    def get_results(self, id=None, state=None, include_task=False,
        task_id=None):
        """ Obtain the results for a specific task.

            Overload the definition of the parent by entering the
            task_id automatically.
        """
        return super().get_results(
            id=id,
            state=state,
            include_task=include_task,
            task_id=task_id,
            node_id=self.whoami.id_
        )

    def is_encrypted_collaboration(self):
        """ Boolean whenever the encryption is enabled.

            End-to-end encryption is per collaboration managed at the
            central server. It is important to note that the local
            configuration-file should allow explicitly for unencrpyted
            messages. This function returns the setting from the server.
        """
        response = self.request(f"collaboration/{self.collaboration_id}")
        return response.get("encrypted") == 1

    def set_task_start_time(self, id: int):
        """ Sets the start time of the task at the central server.

            This is important as this will note that the task has been
            started, and is waiting for restuls.

            :param id: id of the task to set the start-time of

            TODO the initiator_id does not make sens here...
        """
        self.patch_results(id, None, result={
            "started_at": datetime.datetime.now().isoformat()
        })

    def patch_results(self, id: int, initiator_id: int, result: dict):
        """ Update the results at the central server.

            Typically used when to algorithm container is finished or
            when a status-update is posted (started, finished)

            :param id: id of the task to patch
            :param initiator_id: organization id of the origin of the
                task. This is required because we want to encrypt the
                results specifically for him

            TODO: the key `results` is not always present, e.g. when
                only the timestamps are updated
            FIXME: public keys should be cached
        """
        if "result" in result:
            msg = f"retrieving public key from organization={initiator_id}"
            self.log.debug(msg)

            org = self.request(f"organization/{initiator_id}")
            public_key = org["public_key"]

            # self.log.info('Found result (base64 encoded):')
            # self.log.info(bytes_to_base64s(result["result"]))

            result["result"] = self.cryptor.encrypt_bytes_to_str(
                result["result"],
                public_key
            )

            self.log.debug("Sending results to server")
        else:
            self.log.debug("Just patchin'")

        return self.request(f"result/{id}", json=result, method='patch')

