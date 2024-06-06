import json
import os
import re
from urllib.parse import parse_qs

from fedservice.entity.utils import get_federation_entity
from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server.user_authn.authn_context import PASSWORD
from idpyoidc.util import load_yaml_config
from idpyoidc.util import rndstr
from openid4v.client.client_authn import ClientAuthenticationAttestation
import pytest
import responses
from satosa.attribute_mapping import AttributeMapper
from satosa.frontends.base import FrontendModule
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.response import SeeOther
from satosa.state import State
from satosa_idpyop.core import ExtendedContext

from satosa_openid4vci.openid4vci import OpenID4VCIFrontend
from tests import create_trust_chain_messages
from tests import federation_setup
from tests import wallet_setup

BASEDIR = os.path.abspath(os.path.dirname(__file__))
INTERNAL_ATTRIBUTES = {"attributes": {"mail": {"saml": ["email"], "openid": ["email"]}}}
BASE_URL = "https://ci.example.com"
USERS = {
    "diana": {
        "sn": ["Krall"],
        "givenName": ["Diana"],
        "eduPersonAffiliation": ["student"],
        "eduPersonScopedAffiliation": ["student@example.com"],
        "eduPersonPrincipalName": ["test@example.com"],
        "uid": ["diana"],
        "eduPersonTargetedID": ["one!for!all"],
        "c": ["SE"],
        "o": ["Example Co."],
        "ou": ["IT"],
        "initials": ["P"],
        "schacHomeOrganization": ["example.com"],
        "email": ["diana@example.com"],
        "displayName": ["Diana Krall"],
        "norEduPersonNIN": ["SE199012315555"]
    }
}


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


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
        frontend_config = load_yaml_config(full_path("satosa_conf.yaml"))
        _jwks = self.entity["trust_anchor"].keyjar.export_jwks()
        frontend_config["op"]["server_info"]["trust_anchors"] = {
            self.entity["trust_anchor"].entity_id: _jwks}

        frontend = OpenID4VCIFrontend(auth_req_callback_func, INTERNAL_ATTRIBUTES,
                                      frontend_config, BASE_URL, "OIDC")

        frontend.register_endpoints(["entity_configuration", "authorization", "token",
                                     "pushed_authorization", "credential"])
        return frontend

    @pytest.fixture
    def context(self):
        context = ExtendedContext()
        context.state = State()
        return context

    @pytest.fixture
    def authz_details_request(self):
        authz_details = {
            "type": "openid_credential",
            "format": "vc+sd-jwt",
            "credential_definition": {
                "type": "PersonIdentificationData"
            }
        }
        authz_request = {
            'authorization_details': [authz_details],
            'response_type': ['code'],
            'client_id': self.wallet["entity_id"],
            "redirect_uri": self.wallet["redirect_uris"][0]
        }
        return authz_request

    def pick_endpoint(self, frontend, endpoint_path):
        for pattern, instance in frontend.endpoints:
            if re.match(pattern, endpoint_path):
                return instance

    def setup_for_authn_response(self, context: ExtendedContext, frontend: FrontendModule,
                                 auth_req: Message):
        context.state[frontend.name] = {"oidc_request": auth_req.to_urlencoded()}

        auth_info = AuthenticationInformation(
            PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml"
        )
        internal_response = InternalData(auth_info=auth_info)
        internal_response.attributes = AttributeMapper(
            frontend.internal_attributes).to_internal("saml", USERS["diana"])
        internal_response.subject_id = "diana"

        return internal_response

    def _authz_flow(self, client_id, srv, wia, audience, actor, frontend, context):

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

        _state = rndstr()
        kwargs = {"state": _state}

        _service = actor.get_service("authorization")
        _service.certificate_issuer_id = audience
        qeaa_issuer = frontend.app.server.entity_id
        # qeaa_issuer = self.entity["qeaa_issuer"].entity_id

        _cls = ClientAuthenticationAttestation()
        _cls.construct(
            request=authz_request,
            thumbprint=srv.thumbprint_in_cnf_jwk,
            wallet_instance_attestation=wia,
            audience=qeaa_issuer,
            signing_key=self.wallet["wallet"].keyjar.get_signing_key(
                issuer_id=srv.thumbprint_in_cnf_jwk)[0]
        )

        req_info = _service.get_request_parameters(authz_request, client_attestation=_cls, **kwargs)

        assert req_info
        assert set(req_info.keys()) == {"method", "request", "url"}

        # ---- Switch to the server side. The QEEA issuer at the pushed authorization endpoint

        endpoint = self.pick_endpoint(frontend, "authorization")
        context.request = req_info["request"]
        context.request_method = req_info["method"]
        context.request_uri = req_info["url"]

        where_and_what = create_trust_chain_messages(self.entity["wallet_provider"],
                                                     self.entity["trust_anchor"])

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            _pa_response = endpoint(context)

        # _pa_response = endpoint.process_request(_parsed_req)
        assert _pa_response

        internal_response = self.setup_for_authn_response(context, frontend,
                                                          AuthorizationRequest(**authz_request))
        _auth_response = frontend.handle_authn_response(context, internal_response)

        assert isinstance(_auth_response, SeeOther)
        _part = parse_qs(_auth_response.message.split("?")[1])

        # _auth_response = endpoint.process_request(_auth_request)
        return authz_request, _part

    def _token_flow(self, client_id, authz_response, state, authz_request, actor, frontend, context,
                    **kwargs):
        token_request = {
            'grant_type': 'authorization_code',
            'code': authz_response["code"][0],
            'redirect_uri': authz_request["redirect_uri"],
            'client_id': client_id,
            'state': state,
        }
        srv = self.wallet["wallet"].get_service("wallet_instance_attestation")
        qeaa_issuer = self.entity["qeaa_issuer"].entity_id
        wia = srv.wallet_instance_attestation[client_id]

        _cls = ClientAuthenticationAttestation()
        _cls.construct(
            request=token_request,
            thumbprint=srv.thumbprint_in_cnf_jwk,
            wallet_instance_attestation=wia,
            audience=qeaa_issuer,
            signing_key=self.wallet["wallet"].keyjar.get_signing_key(
                issuer_id=srv.thumbprint_in_cnf_jwk)[0]
        )
        _service = actor.get_service("accesstoken")
        req_info = _service.get_request_parameters(token_request, **kwargs)

        # ---- Switch to the server side. The QEEA issuer

        endpoint = self.pick_endpoint(frontend, "token")
        # endpoint = self.entity["qeaa_issuer"]["openid_credential_issuer"].get_endpoint("token")
        context.request = req_info["request"]
        context.request_method = req_info["method"]
        context.request_uri = req_info["url"]
        context.http_info = req_info["headers"]

        _token_response = endpoint(context)
        # _parsed_req = endpoint.parse_request(request=req_info["request"], http_info=_http_info)
        # _token_response = endpoint.process_request(_parsed_req)
        _service.upstream_get("context").cstate.update(state, json.loads(_token_response.message))
        return _token_response

    def _credential_flow(self, token_response, actor, frontend, context, **kwargs):

        # And now for the QEEA issuance
        qeaa_request = {
            'format': 'vc+sd-jwt',
            'credential_definition': {'type': ['PersonIdentificationData']},
            "access_token": token_response["access_token"]
        }
        _service = actor.get_service("credential")
        _federation_entity = get_federation_entity(actor)
        _metadata = _federation_entity.trust_chain["https://qeaa.example.org"][0].metadata
        kwargs["htu"] = _metadata['openid_credential_issuer']["credential_endpoint"]
        cred_req_info = _service.get_request_parameters(qeaa_request, **kwargs)

        assert cred_req_info

        # ---- Switch to the server side. The QEEA issuer

        endpoint = self.pick_endpoint(frontend, "credential")
        # endpoint = self.entity["qeaa_issuer"]["openid_credential_issuer"].get_endpoint("token")
        context.request = cred_req_info["request"]
        context.request_method = cred_req_info["method"]
        context.request_uri = cred_req_info["url"]
        context.http_info = cred_req_info["headers"]

        _cred_response = endpoint(context)

        return _cred_response

    def test_authorization_endpoint(self, context, frontend):
        wallet_provider = self.entity["wallet_provider"]["wallet_provider"]

        # The WIA request by the Wallet
        srv = self.wallet["wallet"].get_service("wallet_instance_attestation")
        req = srv.construct(request_args={"aud": wallet_provider.entity_id, "nonce": "NONCE"})
        assert req["assertion"]
        # Now get the wallet provider to sign

        endpoint = wallet_provider.get_endpoint("wallet_provider_token")
        parsed_request = endpoint.parse_request(request=req)
        response = endpoint.process_request(parsed_request)
        wia = response["response_args"]["assertion"]

        client_id = srv.thumbprint_in_cnf_jwk
        srv.wallet_instance_attestation[client_id] = wia

        # done with the wallet provider, now for the QEEA issuer

        qeaa_issuer = self.entity["qeaa_issuer"].entity_id
        handler = self.wallet["pid_eaa_consumer"]
        _actor = handler.get_consumer(qeaa_issuer)
        if _actor is None:
            actor = handler.new_consumer(qeaa_issuer)
        else:
            actor = _actor

        where_and_what = create_trust_chain_messages(self.entity["qeaa_issuer"],
                                                     self.entity["trust_anchor"])
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            # collect metadata for QEEA issuer
            qeaa_issuer_metadata = self.wallet["federation_entity"].get_verified_metadata(
                qeaa_issuer)

        actor.context.provider_info = qeaa_issuer_metadata['oauth_authorization_server']

        _authz_request, _auth_response = self._authz_flow(client_id, srv, wia, qeaa_issuer, actor,
                                                          frontend=frontend,
                                                          context=context)
        assert _auth_response

        #  token endpoint
        _token_response = self._token_flow(client_id, _auth_response, _authz_request["state"],
                                           _authz_request, actor,
                                           frontend, context)

        _credential_response = self._credential_flow(json.loads(_token_response.message), actor,
                                                     state=_authz_request["state"],
                                                     frontend=frontend, context=context)
        assert _credential_response
