import logging

from cryptojwt import KeyJar
from fedservice.entity_statement.cache import ESCache
from fedservice.entity_statement.statement import TrustChain

logger = logging.getLogger(__name__)


# Doesn't know about ExtendedContext

class FEPersistence(object):

    def __init__(self, storage, upstream_get):
        self.storage = storage
        self.upstream_get = upstream_get

    # Below, federation entity stuff
    def store_federation_cache(self):
        _entity = self.upstream_get("unit")
        _cache = _entity.function.trust_chain_collector.config_cache
        self.storage.store(information_type="entity_configuration", value=_cache.dump())
        _cache = _entity.function.trust_chain_collector.entity_statement_cache
        self.storage.store(information_type="entity_statement", value=_cache.dump())

    def restore_federation_cache(self):
        _entity = self.upstream_get("unit")
        _cache = ESCache()
        _cache.load(self.storage.fetch(information_type="entity_configuration"))
        _entity.function.trust_chain_collector.config_cache = _cache

        _cache = ESCache()
        _cache.load(self.storage.fetch(information_type="entity_statement"))
        _entity.function.trust_chain_collector.entity_statement_cache = _cache

    def store_federation_keys(self):
        _entity = self.upstream_get("unit")
        for entity_id in _entity.keyjar.owners():
            if entity_id == "" or entity_id == _entity.entity_id:
                jwks = _entity.keyjar.export_jwks(private=True, issuer_id=entity_id)
                if entity_id == "":
                    entity_id = "__"
            else:
                jwks = _entity.keyjar.export_jwks(issuer_id=entity_id)
            self.storage.store(information_type="fed_jwks", key=entity_id, value=jwks)

    def restore_federation_keys(self):
        keyjar = KeyJar()
        for entity_id in self.storage.keys_by_information_type("fed_jwks"):
            jwks = self.storage.fetch(information_type="fed_jwks", key=entity_id)
            if entity_id == '__':
                entity_id = ""
            keyjar.import_jwks(jwks, entity_id)
        self.upstream_get("unit").keyjar = keyjar

    def store_trust_chains(self):
        _entity = self.upstream_get("unit")
        if _entity.trust_chain:
            _chains = [tc.dump() for tc in _entity.trust_chain]
            self.storage.store(information_type="trust_chain", value=_chains)

    def restore_trust_chains(self):
        _entity = self.upstream_get("unit")
        _chains = self.storage.fetch(information_type="trust_chain")
        _entity.trust_chain = [TrustChain(**v) for v in _chains]

    def reset_state(self):
        _entity = self.upstream_get("unit")
        _entity.trust_chain = {}
        _entity.keyjar = KeyJar()
        _entity.function.trust_chain_collector.config_cache = {}
        _entity.function.trust_chain_collector.entity_statement_cache = {}

    def store_state(self):
        self.store_trust_chains()
        self.store_federation_keys()
        self.store_federation_cache()

    def restore_state(self):
        self.restore_trust_chains()
        self.restore_federation_keys()
        self.restore_federation_cache()