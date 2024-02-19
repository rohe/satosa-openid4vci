import json
import sys

from fedservice.combo import FederationCombo
from fedservice.utils import make_federation_combo
from idpyoidc.util import load_config_file
from satosa_openid4vci.setup_utils import load_values_from_file

ENTITY = json.loads(open("entities.json", 'r').read())


fed_entity = {}
combo_entity = {}

for ent, info in ENTITY.items():
    _cnf = load_values_from_file(load_config_file(f"{info['dir']}/{info['config']}"))
    _ent = make_federation_combo(**_cnf["entity"])
    if isinstance(_ent, FederationCombo):
        fed_entity[ent] = _ent["federation_entity"]
        combo_entity[ent] = _ent
    else:
        fed_entity[ent] = _ent

_fed_entity = fed_entity[sys.argv[1]]
_tm_issuer = _fed_entity.get_endpoint("status").trust_mark_issuer
entity_id = sys.argv[2]
print (_tm_issuer.create_trust_mark(sys.argv[3], entity_id))
