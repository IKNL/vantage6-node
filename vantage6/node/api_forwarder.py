"""API forwarder.

Module that allows to access an API from an algorithm from the outside
world. This is usefull when two or more nodes need direct communication.

The algorithm needs to request a token first using the password stored
in the environment variable API_FORWARDER_PASSWORD. Then it can handout
this token to another party to access its API.

"""

import requests
import os
import logging
import uuid
import datetime

from flask import Flask, request, jsonify
from flask_jwt_extended.jwt_manager import JWTManager
from flask_jwt_extended import (
    jwt_required,
    create_access_token,
    get_jwt_identity
)
from vantage6.node.util import logger_name


# Setup FLASK
app = Flask(__name__)
log = logging.getLogger(logger_name(__name__))

# TODO make this setable in the config
app.config["JWT_SECRET_KEY"] = str(uuid.uuid1())
jwt = JWTManager(app)


@app.route('/<path:path>',
           methods=["GET", "POST", "PATCH", "PUT", "DELETE"])
@jwt_required
def proxy(path):
    """Generic endpoint that forwards the request to the algorithm container

    The internal adress of the container is encoded in the JWT token that is
    send with the request.

    Parameters
    ----------
    path : str
        path to access on the algorithm container API

    Returns
    -------
    dict
        containing the response of the algorithm container
    """
    log.info(f'request for {path}')

    method_name = request.method.lower()
    method = {
        "get": requests.get,
        "post": requests.post,
        "patch": requests.patch,
        "put": requests.put,
        "delete": requests.delete
    }.get(method_name, requests.get)

    identity = get_jwt_identity()
    forward_ip = identity.get("local_adress")

    api_url = f"{forward_ip}/{path}"

    try:
        response = method(
            api_url,
            json=request.get_json(),
            params=request.args,
        )
    except Exception as e:
        log.error("Unable to forward request...!")
        log.debug(e)
        return

    if response.status_code > 200:
        log.error(f"Algorithm response code {response.status_code}")
        log.debug(response.json().get("msg", "no description..."))

    return jsonify(response.json())


@app.route('/login', methods=["POST"])
def login():
    """Request a token for an algorithm container.

    An algorithm container can request a token for other algorithm containers
    (from different organizations) to access this API and thereby accessing the
    API of the algorithm container.

    Returns
    -------
    dict
        containing the access token
    """
    data = request.json
    password = data.get("password")
    if password == os.environ["API_FORWARDER_PASSWORD"]:
        log.info("successfull login from algorithm")

        # ip adress from the algorithm contain in the local node network
        local_ip = data.get("local_ip")

        # create token that encapsulates the internal ip-adress from the
        # container.
        payload = {
            "local_adress": local_ip
        }

        # TODO make this a setting (or better use refresh tokens...).
        delta = datetime.timedelta(days=7)
        token = create_access_token(identity=payload, expires_delta=delta)

        return jsonify(access_token=token)
