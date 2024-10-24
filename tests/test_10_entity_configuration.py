import os
import sys

import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.util import load_yaml_config
from idpyoidc.util import rndstr
from openid4v.client.client_authn import ClientAuthenticationAttestation
from satosa.state import State
from satosa_idpyop.core import ExtendedContext
from satosa_openid4vci.openid4vci import OpenID4VCIFrontend

from tests import create_trust_chain_messages
from tests import federation_setup
from tests import wallet_setup

BASEDIR = os.path.abspath(os.path.dirname(__file__))

sys.path.insert(0, ".")


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


INTERNAL_ATTRIBUTES = {
    "attributes": {"mail": {"saml": ["email"], "openid": ["email"]}}
}

BASE_URL = "https://ci.example.com"


def auth_req_callback_func(c, x):
    return x


class TestFrontEnd():

    @pytest.fixture(autouse=True)
    def federation_setup(self):
        # Dictionary with all the federation members
        self.entity = federation_setup()
        # The wallet instance
        self.wallet = wallet_setup(self.entity)

    @pytest.fixture
    def frontend(self):
        _ta = self.entity["trust_anchor"]
        trust_anchor_def = {_ta.entity_id: _ta.keyjar.export_jwks()}

        frontend_config = load_yaml_config(full_path("satosa_conf.yaml"))
        frontend_config["op"]["server_info"]["trust_anchors"] = trust_anchor_def

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

    def test_entity_configuration_endpoint(self, context, frontend):
        context.request = {}
        response = frontend.entity_configuration_endpoint(context)
        assert response
        _jws = factory(response.message)
        _payload = _jws.jwt.payload()
        assert _payload
        assert _payload["authority_hints"] == ["https://ta.example.com"]
        assert set(_payload["metadata"].keys()) == {'federation_entity', 'openid_credential_issuer',
                                                    'oauth_authorization_server'}

    def test_authorization_endpoint(self):
        wallet_provider = self.entity["wallet_provider"]["wallet_provider"]

        # The WIA request by the Wallet
        service = self.wallet["wallet"].get_service("wallet_instance_attestation")
        ephemeral_key = service.upstream_get("unit").mint_ephemeral_key()
        req = service.construct(
            request_args={
                "aud": wallet_provider.entity_id, "nonce": "NONCE",
                "challenge": "__not__applicable__",
                "integrity_assertion": "__not__applicable__",
                "hardware_signature": "__not__applicable__",
                "hardware_key_tag": "__not__applicable__",
                "vp_formats_supported": {
                    "jwt_vp_json": {
                        "alg_values_supported": [
                            "ES256"
                        ]
                    },
                    "jwt_vc_json": {
                        "alg_values_supported": [
                            "ES256"
                        ]
                    }
                }
            },
            ephemeral_key=ephemeral_key,
        )
        assert req["assertion"]
        # Now get the wallet provider to sign

        endpoint = wallet_provider.get_endpoint("wallet_provider_token")
        parsed_request = endpoint.parse_request(request=req)
        response = endpoint.process_request(parsed_request)
        wia = response["response_args"]["assertion"]

        client_id = ephemeral_key.kid
        service.wallet_instance_attestation[client_id] = wia

        # done with the wallet provider now for the PID issuer

        pid_issuer = self.entity["pid_issuer"].entity_id
        handler = self.wallet["pid_eaa_consumer"]
        _actor = handler.get_consumer(pid_issuer)
        if _actor is None:
            actor = handler.new_consumer(pid_issuer)
        else:
            actor = _actor

        where_and_what = create_trust_chain_messages(self.entity["pid_issuer"],
                                                     self.entity["trust_anchor"])
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            # collect metadata for PID issuer
            pid_issuer_metadata = self.wallet["federation_entity"].get_verified_metadata(pid_issuer)

        actor.context.provider_info = pid_issuer_metadata['openid_credential_issuer']

        # _service = actor.get_service("authorization")
        # _service.certificate_issuer_id = pid_issuer
        # _a_req = _service.get_request_parameters(
        #     request_args={'authorization_details': [authz_details],
        #                   'redirect_uri': 'eudiw://start.wallet.example.org',
        #                   "state": _state},
        #     endpoint="")

        # Create authorization request
        authz_details = {
            "type": "openid_credential",
            "format": "vc+sd-jwt",
            "credential_definition": {
                "type": "PersonIdentificationData"
            }
        }
        authz_request = {
            'authorization_details': [authz_details],
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': 'eudiw://start.wallet.example.org',
        }

        # Create the client attestation
        _cls = ClientAuthenticationAttestation()
        _cls.construct(
            request=authz_request,
            thumbprint=ephemeral_key.kid,
            wallet_instance_attestation=wia,
            audience=pid_issuer,
            signing_key=self.wallet["wallet"].keyjar.get_signing_key(issuer_id=ephemeral_key.kid)[0]
        )

        _state = rndstr()
        kwargs = {"state": _state}

        _service = actor.get_service("authorization")
        _service.certificate_issuer_id = pid_issuer

        req_info = _service.get_request_parameters(authz_request, **kwargs)

        assert req_info
        assert set(req_info.keys()) == {"method", "request", "url", "headers"}

        # ---- Switch to the server side. The PID issuer

        endpoint = self.entity["pid_issuer"]["openid_credential_issuer"].get_endpoint(
            "pushed_authorization")

        where_and_what = create_trust_chain_messages(self.entity["wallet_provider"],
                                                     self.entity["trust_anchor"])

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _parsed_req = endpoint.parse_request(request=req_info["request"])

        _pa_response = endpoint.process_request(_parsed_req)
        assert _pa_response

        # Now for the authz request to the authz endpoint

        request = {
            "request_uri": _pa_response["http_response"]["request_uri"],
            "redirect_uri": authz_request["redirect_uri"],
            "response_type": ["code"],
            'client_id': client_id
        }

        endpoint = self.entity["pid_issuer"]["openid_credential_issuer"].get_endpoint(
            "authorization")

        _auth_request = endpoint.parse_request(request)
        _auth_response = endpoint.process_request(_auth_request)
        assert _auth_response

        #  token endpoint
        # Create a new client attestation

        token_request = {
            'grant_type': 'authorization_code',
            'code': _auth_response["response_args"]["code"],
            'redirect_uri': authz_request["redirect_uri"],
            'client_id': client_id,
            'state': _state,
        }
        _cls = ClientAuthenticationAttestation()
        _cls.construct(
            request=token_request,
            thumbprint=srv.thumbprint_in_cnf_jwk,
            wallet_instance_attestation=wia,
            audience=pid_issuer,
            signing_key=self.wallet["wallet"].keyjar.get_signing_key(
                issuer_id=srv.thumbprint_in_cnf_jwk)[0]
        )

        _service = actor.get_service("accesstoken")
        req_info = _service.get_request_parameters(token_request, **kwargs)

        # ---- Switch to the server side. The PID issuer

        endpoint = self.entity["pid_issuer"]["openid_credential_issuer"].get_endpoint("token")
        _http_info = {
            "headers": req_info["headers"],
            "method": req_info["method"],
            "url": req_info["url"],
        }

        _parsed_req = endpoint.parse_request(request=req_info["request"], http_info=_http_info)
        _token_response = endpoint.process_request(_parsed_req)
        assert _token_response
        _service.upstream_get("context").cstate.update(_state, _token_response["response_args"])

        # And now for the PID issuance
        pid_request = {
            'format': 'vc+sd-jwt',
            'credential_definition': {'type': ['PersonIdentificationData']},
            "access_token": _token_response["response_args"]["access_token"]
        }
        _service = actor.get_service("credential")
        cred_req_info = _service.get_request_parameters(pid_request, **kwargs)

        assert cred_req_info

        # ---- Switch to the server side. The PID issuer

        endpoint = self.entity["pid_issuer"]["openid_credential_issuer"].get_endpoint("credential")

        _http_info = {
            "headers": cred_req_info["headers"],
            "method": cred_req_info["method"],
            "url": cred_req_info["url"],
        }
        _parsed_req = endpoint.parse_request(request=cred_req_info["request"],
                                             http_info=_http_info)

        _cred_response = endpoint.process_request(_parsed_req)
        assert _cred_response
