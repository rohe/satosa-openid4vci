import os

from cryptojwt.utils import importer
from idpyoidc.server.util import execute

from fedservice.entity import FederationEntity

BASEDIR = os.path.abspath(os.path.dirname(__file__))

# TA_ID = "https://ta.example.org"
# WP_ID = "https://wp.example.org"
# TMI_ID = "https://tmi.example.org"
# WALLET_ID = "I_am_the_wallet"
#
# FEDERATION_CONFIG = {
#     TA_ID: {
#         "entity_type": "trust_anchor",
#         "subordinates": [WP_ID, TMI_ID],
#         "kwargs": {
#             "preference": {
#                 "organization_name": "The example federation operator",
#                 "homepage_uri": "https://ta.example.org",
#                 "contacts": "operations@ta.example.org"
#             },
#             "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
#         }
#     },
#     WP_ID: {
#         "entity_type": "wallet_provider",
#         "trust_anchors": [TA_ID],
#         "kwargs": {
#             "authority_hints": [TA_ID],
#             "preference": {
#                 "organization_name": "The Wallet Provider",
#                 "homepage_uri": "https://wp.example.com",
#                 "contacts": "operations@wp.example.com"
#             }
#         }
#     },
#     TMI_ID: {
#         "entity_type": "wallet_provider",
#         "trust_anchors": [TA_ID],
#         "kwargs": {
#             "authority_hints": [TA_ID],
#             "preference": {
#                 "organization_name": "The Wallet Provider",
#                 "homepage_uri": "https://wp.example.com",
#                 "contacts": "operations@wp.example.com"
#             }
#         }
#     },
#     WALLET_ID: {
#         "entity_type": "wallet",
#         "trust_anchors": [TA_ID],
#         "kwargs": {}
#     }
# }



def execute_function(function, **kwargs):
    if isinstance(function, str):
        return importer(function)(**kwargs)
    else:
        return function(**kwargs)


def make_entity(entity_id, entity_type, **kwargs):
    kwargs["preference"] = kwargs.get("preference", {})
    kwargs["entity_id"] = entity_id

    try:
        entity = execute_function(f'entities.{entity_type}.main', **kwargs)
    except ModuleNotFoundError:
        entity = execute_function(f'tests.entities.{entity_type}.main', **kwargs)

    return entity


def get_subordinate_info(entity):
    if isinstance(entity, FederationEntity):
        fed_ent = entity
        entity_types = ["federation_entity"]
    else:
        fed_ent = entity["federation_entity"]
        entity_types = entity.keys()

    jwks = fed_ent.keyjar.export_jwks()
    return {"jwks": jwks, "entity_types": entity_types, "authority_hints": fed_ent.context.authority_hints}


def get_trust_anchor_info(entity):
    if isinstance(entity, FederationEntity):
        fed_ent = entity
    else:
        fed_ent = entity["federation_entity"]

    jwks = fed_ent.keyjar.export_jwks()
    return {"jwks": jwks}


def build_federation(federation_conf):
    entity = {}
    for entity_id, item in federation_conf.items():
        entity[entity_id] = make_entity(entity_id, item["entity_type"], **item["kwargs"])

    for entity_id, ent in entity.items():
        subordinates = federation_conf[entity_id].get("subordinates", None)
        if isinstance(ent, FederationEntity):
            fed_ent = ent
        else:
            fed_ent = ent["federation_entity"]
        if subordinates:
            if isinstance(subordinates, list):
                for sub in subordinates:
                    fed_ent.server.subordinate[sub] = get_subordinate_info(entity[sub])
            else:
                fed_ent.server.subordinate = execute(subordinates)
        trust_anchor = federation_conf[entity_id].get("trust_anchors", None)
        if trust_anchor:
            for ta_entity_id in trust_anchor:
                _info = get_trust_anchor_info(entity[ta_entity_id])
                fed_ent.add_trust_anchor(ta_entity_id, _info["jwks"])

    return entity


if __name__ == '__main__':
    entity = build_federation(FEDERATION)
