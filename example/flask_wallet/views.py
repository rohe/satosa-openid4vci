import json
import logging
from urllib.parse import parse_qs

import werkzeug
from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from cryptojwt.utils import b64e
from fedservice.entity import get_verified_trust_chains
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask.helpers import send_from_directory
from idpyoidc.client.defaults import CC_METHOD
from idpyoidc.util import rndstr
from idpysdjwt.verifier import display_sdjwt
from openid4v.message import WalletInstanceAttestationJWT

logger = logging.getLogger(__name__)

entity = Blueprint('entity', __name__, url_prefix='')


def hash_func(value):
    _hash_method = CC_METHOD["S256"]
    _hv = _hash_method(value.encode()).digest()
    return b64e(_hv).decode("ascii")


def compact(qsdict):
    res = {}
    for key, val in qsdict.items():
        if len(val) == 1:
            res[key] = val[0]
        else:
            res[key] = val
    return res


@entity.route('/static/<path:path>')
def send_js(path):
    return send_from_directory('static', path)


@entity.route('/')
def index():
    return render_template('base.html')


@entity.route('/img/<path:path>')
def send_image(path):
    return send_from_directory('img', path)


@entity.route('/wallet_provider')
def wallet_provider():
    wp_id = request.args["entity_id"]
    session["wallet_provider_id"] = wp_id
    trust_chain = current_app.federation_entity.get_trust_chains(wp_id)

    return render_template('wallet_provider.html',
                           trust_chain_path=trust_chain[0].iss_path,
                           metadata=trust_chain[0].metadata)


@entity.route('/app_attestation')
def app_attestation():
    # This is where the attestation request is constructed and sent to the Wallet Provider.
    # And where the response is unpacked.
    wallet_entity = current_app.server["wallet"]
    wallet_provider_id = session["wallet_provider_id"]

    # APP Attestation
    trust_chains = current_app.federation_entity.get_trust_chains(wallet_provider_id)

    request_args = {}
    resp = wallet_entity.do_request(
        "app_attestation",
        request_args=request_args,
        endpoint=trust_chains[0].metadata['wallet_provider']['app_attestation_endpoint'])

    session["nonce"] = resp["nonce"]
    return render_template('app_attestation.html',
                           app_attestation_request=json.dumps({"iccid": "89470000000000000001"}),
                           app_attestation_response=resp)


@entity.route('/wallet_instance_attestation')
def wallet_instance_attestation():
    # This is where the attestation request is constructed and sent to the Wallet Provider.
    # And where the response is unpacked.
    wallet_entity = current_app.server["wallet"]
    wallet_provider_id = session["wallet_provider_id"]

    trust_chains = current_app.federation_entity.get_trust_chains(wallet_provider_id)
    trust_chain = trust_chains[0]

    # WIA request
    _service = wallet_entity.get_service("wallet_instance_attestation")
    _service.wallet_provider_id = wallet_provider_id

    request_args = {"nonce": session["nonce"], "aud": wallet_provider_id}

    # this is just to be able to show what's sent
    req_info = _service.get_request_parameters(
        request_args,
        endpoint=trust_chain.metadata['wallet_provider']['token_endpoint'])
    _ra_jwt = factory(req_info["request"]["assertion"])
    req_assertion = _ra_jwt.jwt.payload()
    req_assertion["iss"] = "__jwk_thumbprint__"
    req_assertion["cnf"]["kid"] = "__jwk_thumbprint__"
    _request_headers = _ra_jwt.jwt.headers.copy()
    _request_headers["kid"] = "__jwk_thumbprint__"

    # This is where the request is actually sent
    resp = wallet_entity.do_request(
        "wallet_instance_attestation",
        request_args=request_args,
        endpoint=trust_chain.metadata['wallet_provider']['token_endpoint'])

    wallet_instance_attestation = resp["assertion"]

    _jwt = JWT(key_jar=wallet_entity.keyjar)
    _jwt.msg_cls = WalletInstanceAttestationJWT
    _ass = _jwt.unpack(token=wallet_instance_attestation)
    session["thumbprint_in_cnf_jwk"] = _ass["cnf"]["jwk"]["kid"]

    del req_info["request"]

    return render_template('wallet_instance_attestation.html',
                           req_assertion=req_assertion,
                           request_headers=_request_headers,
                           req_info=req_info,
                           wallet_instance_attestation=_ass,
                           response_headers=_ass.jws_header)


@entity.route('/picking_pid_issuer')
def picking_pid_issuer():
    res = []
    ta_id = list(current_app.federation_entity.trust_anchors.keys())[0]
    list_resp = current_app.federation_entity.do_request('list', entity_id=ta_id)

    # print(f"Subordinates to TA: {list_resp}")
    for entity_id in list_resp:
        # first find out if the entity is an openid credential issuer
        _metadata = current_app.federation_entity.get_verified_metadata(entity_id)
        if "openid_credential_issuer" in _metadata:
            res.append(entity_id)
        res.extend(
            current_app.federation_entity.trawl(ta_id, entity_id,
                                                entity_type="openid_credential_issuer"))

    credential_issuers = res

    _oci = {}
    credential_type = "PersonIdentificationData"
    for pid in res:
        oci_metadata = current_app.federation_entity.get_verified_metadata(pid)
        # logger.info(json.dumps(oci_metadata, sort_keys=True, indent=4))
        for cs in oci_metadata['openid_credential_issuer']["credentials_supported"]:
            if credential_type in cs["credential_definition"]["type"]:
                _oci[pid] = oci_metadata
                break

    pid_issuers = list(_oci.keys())

    pid_issuer_to_use = []
    tmi = {}
    se_pid_issuer_tm = 'http://dc4eu.example.com/PersonIdentificationData/se'
    for eid, metadata in _oci.items():
        _trust_chain = current_app.federation_entity.get_trust_chains(eid)[0]
        _entity_conf = _trust_chain.verified_chain[-1]
        if "trust_marks" in _entity_conf:
            tmi[eid] = []
            for _mark in _entity_conf["trust_marks"]:
                _verified_trust_mark = current_app.federation_entity.verify_trust_mark(
                    _mark, check_with_issuer=True)
                if _verified_trust_mark:
                    tmi[eid].append(_verified_trust_mark)
                    if _verified_trust_mark.get("id") == se_pid_issuer_tm:
                        pid_issuer_to_use.append(eid)
                else:
                    logger.warning("Could not verify trust mark")

    session["pid_issuer_to_use"] = pid_issuers[0]

    return render_template('picking_pid_issuer.html',
                           credential_issuers=credential_issuers,
                           pid_issuers=pid_issuers,
                           trust_marks=tmi,
                           pid_issuer_to_use=pid_issuer_to_use)


@entity.route('/authz')
def authz():
    pid_issuer = session["pid_issuer_to_use"]
    actor = current_app.server["pid_eaa_consumer"]
    _actor = actor.get_consumer(pid_issuer)
    if _actor is None:
        actor = actor.new_consumer(pid_issuer)
    else:
        actor = _actor

    b64hash = hash_func(pid_issuer)
    _redirect_uri = f"https://127.0.0.1:5005/authz_cb/{b64hash}"
    session["redirect_uri"] = _redirect_uri
    _thumbprint = session["thumbprint_in_cnf_jwk"]
    wallet_entity = current_app.server["wallet"]
    request_args = {
        "authorization_details": [
            {
                "type": "openid_credential",
                "format": "vc+sd-jwt",
                "credential_definition": {
                    "type": "PersonIdentificationData"
                }
            }
        ],
        "response_type": "code",
        "client_id": _thumbprint,
        "redirect_uri": _redirect_uri,
    }
    kwargs = {
        "state": rndstr(24),
        "behaviour_args": {
            "wallet_instance_attestation": wallet_entity.context.wallet_instance_attestation[_thumbprint]["attestation"]
        }
    }
    session["state"] = kwargs["state"]

    _service = actor.get_service("authorization")
    _service.certificate_issuer_id = pid_issuer

    # par_req_info = get_request_parameters(
    #     request_args, service=_service,
    #     wallet_instance_attestation=wallet_entity.context.wallet_instance_attestation[_thumbprint]["attestation"],
    #     state=kwargs["state"]
    # )
    # session["par_req"] = {k:v[0] for k,v in parse_qs(par_req_info["body"]).items()}

    req_info = _service.get_request_parameters(request_args, **kwargs)

    session["auth_req_uri"] = req_info['url']
    logger.info(f"Redirect to: {req_info['url']}")
    response = redirect(req_info["url"], 303)
    return response


def get_consumer(issuer):
    actor = current_app.server["pid_eaa_consumer"]
    _consumer = None
    for iss in actor.issuers():
        if hash_func(iss) == issuer:
            _consumer = actor.get_consumer(iss)
            break

    return _consumer


@entity.route('/authz_cb/<issuer>')
def authz_cb(issuer):
    _consumer = get_consumer(issuer)

    # if _consumer is None
    # -- some error message

    _consumer.finalize_auth(request.args)
    session["issuer"] = issuer
    return render_template('authorization.html',
                           #par_request=session["par_req"],
                           auth_req_uri=session["auth_req_uri"],
                           response=request.args.to_dict())


@entity.route('/token')
def token():
    consumer = get_consumer(session["issuer"])
    _req_args = consumer.context.cstate.get_set(session["state"], claim=["redirect_uri", "code",
                                                                         "nonce"])
    trust_chains = get_verified_trust_chains(consumer, consumer.context.issuer)
    trust_chain = trust_chains[0]
    _thumbprint = session["thumbprint_in_cnf_jwk"]
    wallet_entity = current_app.server["wallet"]
    _args = {
        "audience": consumer.context.issuer,
        "thumbprint": _thumbprint,
        "wallet_instance_attestation":
            wallet_entity.context.wallet_instance_attestation[_thumbprint]["attestation"],
        "signing_key": wallet_entity.keyjar.get_signing_key(kid=_thumbprint)[0]
    }
    _nonce = _req_args.get("nonce", "")
    if _nonce:
        _args["nonce"] = _nonce
    _lifetime = consumer.context.config["conf"].get("jwt_lifetime")
    if _lifetime:
        _args["lifetime"] = _lifetime

    _request_args = {
        "code": _req_args["code"],
        "grant_type": "authorization_code",
        "redirect_uri": _req_args["redirect_uri"],
        "state": session["state"]
    }

    _service = consumer.get_service("accesstoken")
    req_info = _service.get_request_parameters(_request_args, **_args)

    resp = consumer.do_request(
        "accesstoken",
        request_args=_request_args,
        endpoint=trust_chain.metadata['oauth_authorization_server']['token_endpoint'],
        state=session["state"],
        **_args
    )
    del req_info["request"]
    return render_template('token.html', request=req_info, response=resp)


@entity.route('/credential')
def credential():
    consumer = get_consumer(session["issuer"])
    _req_args = consumer.context.cstate.get_set(session["state"], claim=["access_token"])
    trust_chains = get_verified_trust_chains(consumer, consumer.context.issuer)
    trust_chain = trust_chains[0]
    wallet_entity = current_app.server["wallet"]
    wallet_entity.keyjar.load_keys(issuer_id=consumer.context.issuer,
                                   jwks_uri=trust_chain.metadata["openid_credential_issuer"]["jwks_uri"])
    consumer.context.keyjar = wallet_entity.keyjar

    _request_args = {
        "format": "vc+sd-jwt",
        "credential_definition": {
            "type": ["PersonIdentificationData"]
        }
    }
    _service = consumer.get_service("credential")
    req_info = _service.get_request_parameters(_request_args, access_token=_req_args["access_token"],
                                               state=session["state"])

    resp = consumer.do_request(
        "credential",
        request_args=_request_args,
        access_token=_req_args["access_token"],
        state=session["state"],
        endpoint=trust_chain.metadata['openid_credential_issuer']['credential_endpoint']
    )

    _jwt, _displ = display_sdjwt(resp["credential"])
    del req_info["request"]
    return render_template('credential.html', request=req_info,
                           response=resp, signed_jwt=_jwt,
                           display=_displ)


@entity.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400
