import base64
import os
import shutil
from typing import Optional

import pytest
from cryptojwt.key_jar import init_key_jar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.util import execute
from openid4v.openid_credential_issuer import OpenidCredentialIssuer
from satosa_idpyop.core import ExtendedContext
from satosa_idpyop.utils import IdpyOPUtils

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


class App(object):

    def __init__(self, storage, server=None):
        self.storage = storage
        self.server = server


STORE_CONF = {
    "class": "satosa_idpyop.core.storage.file.FilesystemDB",
    "kwargs": {
        "fdir": "storage",
        "key_conv": "idpyoidc.util.Base64",
        "value_conv": "idpyoidc.util.JSON"
    }
}

CRYPT_CONFIG = {
    "kwargs": {
        "keys": {
            "key_defs": [
                {"type": "OCT", "use": ["enc"], "kid": "password"},
                {"type": "OCT", "use": ["enc"], "kid": "salt"},
            ]
        },
        "iterations": 1,
    }
}

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

SERVER_CONF = {
    "issuer": "https://example.com/",
    "httpc_params": {"verify": False, "timeout": 1},
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "keys": {"key_defs": DEFAULT_KEY_DEFS, "uri_path": "static/jwks.json"},
    "jwks_uri": "https://example.com/jwks.json",
    "persistence": {
        "class": "satosa_idpyop.persistence.openid_provider.OPPersistence",
        "kwargs": {
            "storage": {
                "class": "satosa_idpyop.core.storage.file.FilesystemDB",
                "kwargs": {
                    "fdir": "op_storage",
                    "key_conv": "idpyoidc.util.Base64",
                    "value_conv": "idpyoidc.util.JSON"
                }
            }
        }
    },
    "token_handler_args": {
        "jwks_def": {
            "private_path": "private/token_jwks.json",
            "read_only": False,
            "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
        },
        "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "add_claims": True,
                "add_claims_by_scope": True,
                "aud": ["https://example.org/appl"],
            },
        },
        "refresh": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "aud": ["https://example.org/appl"],
            },
        },
        "id_token": {
            "class": "idpyoidc.server.token.id_token.IDToken",
            "kwargs": {
                "base_claims": {
                    "email": {"essential": True},
                    "email_verified": {"essential": True},
                }
            },
        },
    },
    "session_params": SESSION_PARAMS,
    "template_dir": "template",
    "claims_interface": {
        "class": "idpyoidc.server.session.claims.ClaimsInterface",
        "kwargs": {},
    },
    "userinfo": {
        "class": "idpyoidc.server.user_info.UserInfo",
        "kwargs": {"db_file": full_path("users.json")},
    },
}

CLIENT_INFO_1 = {
    "client_id": "client_1",
    "client_secret": "paaaasssswoord",
    "redirect_uris": [
        "https://client.example.org/callback",
        "https://client.example.org/callback2",
    ],
    "token_endpoint_auth_method": "client_secret_basic",
    "jwks_uri": "https://client.example.org/my_public_keys.jwks",
    "contacts": ["ve7jtb@example.org", "mary@example.org"],
}
KEYJAR_1 = init_key_jar(key_defs=DEFAULT_KEY_DEFS)
AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE_ABC",
    response_type="code",
)


class TestPersistence(object):

    @pytest.fixture(autouse=True)
    def create_persistence_layer(self):
        # clena up after last time
        try:
            shutil.rmtree("storage")
        except FileNotFoundError:
            pass

        storage = execute(STORE_CONF)
        self.app = App(storage=storage)
        self.utils = IdpyOPUtils(self.app)

        self.app.server = OpenidCredentialIssuer(SERVER_CONF)
        self.session_manager = self.app.server.context.session_manager
        self.user_id = "diana"

    def _create_session(self, auth_req, sub_type="public", sector_identifier="",
                        user_id: Optional[str] = "diana"):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req

        client_id = authz_req["client_id"]
        ae = create_authn_event(user_id)
        return self.app.server.context.session_manager.create_session(
            ae, authz_req, user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_code(self, grant, session_id):
        _server = self.app.server
        _sman = _server.context.session_manager
        # Constructing an authorization code is now done
        _code = grant.mint_token(
            session_id,
            context=_server.context,
            token_class="authorization_code",
            token_handler=_sman.token_handler["authorization_code"]
        )

        _sman.set(_sman.decrypt_session_id(session_id), grant)

        return _code

    def _mint_access_token(self, grant, session_id, token_ref=None):
        _server = self.app.server
        _sman = _server.context.session_manager
        _session_info = _sman.get_session_info(session_id, client_session_info=True)

        _token = grant.mint_token(
            session_id=session_id,
            context=_server.context,
            token_class="access_token",
            token_handler=_sman.token_handler["access_token"],
            based_on=token_ref,  # Means the token (token_ref) was used to mint this token
        )

        _sman.set([self.user_id, _session_info["client_id"], grant.id], grant)

        return _token

    def _client_registration(self,
                             client_info: dict,
                             jwks: Optional[dict] = None,
                             jwks_uri: Optional[str] = ""):
        _context = self.app.server.context
        _context.cdb[client_info["client_id"]] = client_info
        if jwks:
            _context.keyjar.import_jwks(jwks, client_info["client_id"])
        if jwks_uri:
            pass

    def test_load_cdb(self):
        self._client_registration(CLIENT_INFO_1, jwks=KEYJAR_1.export_jwks())
        self.app.server.persistence.store_client_info(CLIENT_INFO_1["client_id"])

        context = ExtendedContext()

        # The simple case
        client_info = self.app.server.persistence.restore_client_info(client_id=CLIENT_INFO_1["client_id"])
        assert client_info == CLIENT_INFO_1

        credentials = f"{CLIENT_INFO_1['client_id']}:{CLIENT_INFO_1['client_secret']}"
        token = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = f"Basic {token}"
        client_info = self.app.server.persistence.restore_client_info(CLIENT_INFO_1["client_id"])
        assert client_info == CLIENT_INFO_1

        session_id = self._create_session(AUTH_REQ)
        grant = self.app.server.context.authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)
        context.request_authorization = f"Bearer {access_token.value}"
        client_info = self.app.server.persistence.restore_client_info(CLIENT_INFO_1["client_id"])
        assert client_info == CLIENT_INFO_1
