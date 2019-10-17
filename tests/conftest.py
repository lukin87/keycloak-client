# -*- coding: utf-8 -*-
import os
import json

import pytest

from keycloak import Client as KeycloakClient
from keycloak.config import config, Client, OpenId, Uma2


here = os.path.dirname(os.path.realpath(__file__))


def read_json(file, cls=None):
    path = os.path.join(here, "data", file)
    with open(path, "r") as f:
        data = json.loads(f.read())
        return cls(**data) if cls else data


client = read_json("client.json", Client)
openid = read_json("openid.json", OpenId)
uma2 = read_json("uma2.json", Uma2)
certs = read_json("certs.json")


@pytest.fixture(autouse=True)
def configs(monkeypatch):
    monkeypatch.setattr("keycloak.config.Config.client", client)
    monkeypatch.setattr("keycloak.config.Config.openid", openid)
    monkeypatch.setattr("keycloak.config.Config.uma2", uma2)
    monkeypatch.setattr("keycloak.mixins.jwt.JWTMixin._certs", certs)


@pytest.fixture()
def kc_config(monkeypatch):
    yield config


@pytest.fixture()
def kc_client(monkeypatch):
    yield KeycloakClient(redirect_uri="http://localhost/kc/callback")
