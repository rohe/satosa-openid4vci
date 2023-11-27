import base64
import logging
from typing import Optional
from typing import Union

from cryptojwt import as_unicode
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.exception import BadSignature
from cryptojwt.exception import Invalid
from cryptojwt.exception import MissingKey
from cryptojwt.utils import as_bytes
from idpyoidc.message import Message
from idpyoidc.message.oidc import JsonWebToken
from idpyoidc.server.client_authn import basic_authn
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.util import sanitize

logger = logging.getLogger(__name__)


# Doesn't know about ExtendedContext

class Persistence(object):

    def __init__(self, app=None):
        self.app = app

    def flush_session_manager(self, session_manager=None):
        """
        each OAuth2/OIDC request loads an oidcop session in memory
        this method will simply free the memory from any loaded session
        """
        if not session_manager:
            session_manager = self.app.server.context.session_manager

        session_manager.flush()

    def reset_state(self):
        _session_manager = self.app.server.context.session_manager
        self.flush_session_manager(_session_manager)
        _context = self.app.server.context
        _context.cdb = {}
        # Get rid of all keys apart from my own by creating a new keyjar with only my keys
        jwks_1 = _context.keyjar.export_jwks(private=True, issuer_id="")
        jwks_2 = _context.keyjar.export_jwks(private=True, issuer_id=_context.entity_id)
        keyjar = KeyJar()
        keyjar.import_jwks(jwks_1, "")
        keyjar.import_jwks(jwks_2, issuer_id=_context.entity_id)
        self.app.server.keyjar = keyjar
        _context.keyjar = self.app.server.keyjar

    def _deal_with_client_assertion(self, sman, token):
        _keyjar = sman.upstream_get("attribute", "keyjar")
        _jwt = JWT(_keyjar)
        _jwt.msg_cls = JsonWebToken
        try:
            ca_jwt = _jwt.unpack(token)
        except (Invalid, MissingKey, BadSignature) as err:
            logger.info("%s" % sanitize(err))
            raise ClientAuthenticationError("Could not verify client_assertion.")
        return ca_jwt["iss"]

    def _get_client_id(self,
                       session_manager,
                       request: Union[Message, dict],
                       http_info: dict) -> Optional[str]:
        # Figure out which client is concerned
        if "client_id" in request:
            return request["client_id"]

        for param in ["code", "access_token", "refresh_token", "registration_access_token"]:
            if param in request:
                _token_info = session_manager.token_handler.info(request[param])
                sid = _token_info["sid"]
                _path = session_manager.decrypt_branch_id(sid)
                return _path[1]

        if "client_assertion" in request:
            return self._deal_with_client_assertion(session_manager, request["client_assertion"])

        authz = http_info.get("headers", {}).get("authorization", "")
        if authz:
            if "Basic " in authz:
                token = authz.split(" ", 1)[1]
                _info = basic_authn(token)
                return _info["id"]
            else:
                token = authz.split(" ", 1)[1]
                _token_info = session_manager.token_handler.info(token)
                sid = _token_info["sid"]
                _path = session_manager.decrypt_branch_id(sid)
                return _path[1]

        return None

    def restore_state(self,
                     request: Union[Message, dict],
                     http_info: Optional[dict]):
        sman = self.app.server.context.session_manager
        _session_info = self.app.storage.fetch(information_type="session_info", key="")

        self.flush_session_manager(sman)
        sman.load(_session_info)

        # Find the client_id
        client_id = self._get_client_id(sman, request=request, http_info=http_info)
        # Update session
        _client_session_info = self.app.storage.fetch(information_type="client_session_info",
                                                      key=client_id)
        _session_info["db"] = _client_session_info

        self.flush_session_manager(sman)
        sman.load(_session_info)

        # Update client database
        self.restore_client_info(client_id)

    def load_claims(self, client_id):
        return self.app.storage.fetch(information_type="claims", key=client_id)

    # Now for the store part

    def store_claims(self, claims: dict, client_id: str):
        self.app.storage.store(information_type="claims", value=claims, key=client_id)

    def _get_client_session_info(self, client_id, db):
        sman = self.app.server.context.session_manager
        res = {}
        for key, info in db.items():
            val = sman.unpack_branch_key(key)
            if len(val) > 1 and val[1] == client_id:
                res[key] = info
                if val[0] not in res:
                    res[val[0]] = db[val[0]]
        return res

    def store_state(self, client_id):
        sman = self.app.server.context.session_manager
        _session_state = sman.dump()
        _client_session_info = self._get_client_session_info(client_id, _session_state["db"])
        self.app.storage.store(information_type="client_session_info",
                               value=_client_session_info,
                               key=client_id)
        self.store_client_info(client_id)
        _session_state["db"] = {}
        self.app.storage.store(information_type="session_info", value=_session_state)

    def store_client_info(self, client_id):
        _context = self.app.server.context
        # client info
        self.app.storage.store(information_type="client_info", key=client_id,
                               value=_context.cdb[client_id])
        # client keys
        self.app.storage.store(information_type="jwks", key=client_id,
                               value=_context.keyjar.export_jwks(issuer=client_id))

    def restore_client_info(self, client_id: str):
        _context = self.app.server.context
        client_info = self.app.storage.fetch(information_type="client_info", key=client_id)
        _context.cdb[client_id] = client_info
        jwks = self.app.storage.fetch(information_type="jwks", key=client_id)
        _context.keyjar.import_jwks(jwks, client_id)

    def restore_client_info_by_bearer_token(self, request_authorization: str):
        access_token = request_authorization.replace("Bearer ", "")
        sman = self.app.server.context.session_manager
        _session_info = sman.get_session_info_by_token(
            access_token, grant=True, handler_key="access_token"
        )
        return self.restore_client_info(_session_info["client_id"])

    def restore_client_info_by_basic_auth(self, http_authorization):
        _token = http_authorization.replace("Basic ", "")
        _tok = as_bytes(_token)
        # Will raise ValueError type exception if not base64 encoded
        _tok = base64.b64decode(_tok)
        part = as_unicode(_tok).split(":", 1)
        if len(part) != 2:
            raise ValueError("Illegal token")
        return self.restore_client_info(part[0])

    def get_claims_from_sid(self, sid):
        sman = self.app.server.context.session_manager
        _user_id, _client_id, _grant_id = sman.decrypt_session_id(sid)
        return self.app.storage.fetch(information_type="claims", key=_user_id)

    def get_registered_client_ids(self):
        return self.app.storage.keys_by_information_type("client_info")
