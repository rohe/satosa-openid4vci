import base64
import logging
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt import as_unicode
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

    # Below, federation entity stuff
    def store_federation_cache(self):
        _cache = self.app.federation_entity.function.trust_chain_collector.config_cache
        self.app.storage.store(information_type="entity_configuration", value=_cache)
        _cache = self.app.federation_entity.function.trust_chain_collector.entity_statement_cache
        self.app.storage.store(information_type="entity_statement", value=_cache)

    def restore_federation_cache(self):
        _cache = self.app.storage.fetch(information_type="entity_configuration")
        self.app.federation_entity.function.trust_chain_collector.config_cache = _cache
        _cache = self.app.storage.fetch(information_type="entity_statement")
        self.app.federation_entity.function.trust_chain_collector.entity_statement_cache = _cache

    def store_federation_keys(self):
        for entity_id in self.app.federation_entity.keyjar.issuers():
            if entity_id == "" or entity_id == self.app.federation_entity.entity_id:
                jwks = self.app.federation_entity.keyjar.export_jwks(private=True,
                                                                     issuer_id=entity_id)
            else:
                jwks = self.app.federation_entity.keyjar.export_jwks(issuer_id=entity_id)
            self.app.storage.store(information_type="fed_jwks", key=entity_id, value=jwks)

    def restore_federation_keys(self):
        keyjar = KeyJar()
        for entity_id in self.app.storage.keys_by_information_type("fed_jwks"):
            jwks = self.app.storage.fetch(information_type="fed_jwks", key=entity_id)
            keyjar.import_jwks(jwks, entity_id)
        self.app.federation_entity.keyjar = keyjar