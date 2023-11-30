import os

import pytest
from idpyoidc.util import load_yaml_config
from satosa.state import State
from satosa_openid4vci.core import ExtendedContext
from satosa_openid4vci.openid4vci import OpenID4VCIFrontend

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


INTERNAL_ATTRIBUTES = {
    "attributes": {"mail": {"saml": ["email"], "openid": ["email"]}}
}

BASE_URL = "https://ci.example.com"

def auth_req_callback_func(x):
    return x

class TestFrontEnd():

    @pytest.fixture
    def frontend(self):
        frontend_config = load_yaml_config("satosa_conf.yaml")
        # will use in-memory storage
        frontend = OpenID4VCIFrontend(auth_req_callback_func, INTERNAL_ATTRIBUTES,
                                      frontend_config, BASE_URL, "openid4vci_frontend")
        frontend.register_endpoints(["entity_configuration", "authorization", "token",
                                     "pushed_authorization", "credential"])
        return frontend

    @pytest.fixture
    def context(self):
        context = ExtendedContext()
        context.state = State()
        return context

    def test_entity_configuration(self, context, frontend):
        e_conf = frontend.entity_configuration_endpoint()
        assert e_conf
