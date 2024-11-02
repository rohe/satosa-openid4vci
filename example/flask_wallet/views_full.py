import logging

from cryptojwt import JWT
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.utils import as_unicode
from cryptojwt.utils import b64e
from fedservice.entity import get_verified_trust_chains
from fedservice.keyjar import import_jwks
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask.helpers import send_from_directory
from idpyoidc.client.defaults import CC_METHOD
from idpyoidc.key_import import import_jwks
from idpyoidc.util import rndstr
from idpysdjwt.verifier import display_sdjwt
from openid4v.message import WalletInstanceAttestationJWT
import werkzeug

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


@entity.route('/wir_challenge', methods=['GET'])
def challenge1():
    wallet_entity = current_app.server["wallet"]
    wallet_provider_id = session["wallet_provider_id"]

    _challenge = wallet_entity.request_challenge(wallet_provider_id)

    wallet_entity.context.crypto_hardware_key = new_ec_key('P-256')

    session["challenge_wir"] = _challenge

    return render_template('wir_challenge.html', challenge_response=_challenge)


@entity.route('/wai_challenge', methods=['GET'])
def challenge2():
    wallet_entity = current_app.server["wallet"]
    wallet_provider_id = session["wallet_provider_id"]

    _challenge = wallet_entity.request_challenge(wallet_provider_id)

    session["challenge_wai"] = _challenge

    return render_template('wai_challenge.html', challenge_response=_challenge)


@entity.route('/key_attestation', methods=['GET'])
def attest_key():
    wallet_entity = current_app.server["wallet"]
    wallet_provider_id = session["wallet_provider_id"]
    challenge = session["challenge_wir"]

    crypto_hardware_key_tag = wallet_entity.context.crypto_hardware_key.kid

    request_args = {
        "challenge": challenge,
        # "crypto_hardware_key_tag": crypto_hardware_key_tag,
        "crypto_hardware_key": wallet_entity.context.crypto_hardware_key.serialize()
    }

    resp = wallet_entity.request_key_attestation(wallet_provider_id, challenge)

    return render_template('key_attestation.html', key_attestation_response=resp,
                           key_attestation_request=request_args,
                           crypto_hardware_key_tag=crypto_hardware_key_tag)


@entity.route('/wallet_registration', methods=['GET'])
def registration():
    wallet_entity = current_app.server["wallet"]
    wallet_provider_id = session["wallet_provider_id"]
    challenge = session["challenge_wir"]

    resp = wallet_entity.request_registration(wallet_provider_id, challenge)

    # only for display
    _init_reg_info = wallet_entity.context.init_reg[challenge]
    request_args = {
        "challenge": challenge,
        "key_attestation": as_unicode(_init_reg_info["key_attestation"]),
        "hardware_key_tag": _init_reg_info["crypto_hardware_key_tag"]
    }

    return render_template('wallet_registration.html', registration_response=resp,
                           registration_request=request_args)


@entity.route('/wallet_provider')
def wallet_provider():
    wp_id = request.args["entity_id"]
    session["wallet_provider_id"] = wp_id
    wallet_entity = current_app.server["wallet"]

    trust_chain = wallet_entity.get_trust_chains(wp_id)

    return render_template('wallet_provider.html',
                           trust_chain_path=trust_chain[0].iss_path,
                           metadata=trust_chain[0].metadata)


@entity.route('/integrity')
def integrity():
    # This is where the attestation request is constructed and sent to the Wallet Provider.
    # And where the response is unpacked.
    wallet_entity = current_app.server["wallet"]
    wallet_provider_id = session["wallet_provider_id"]
    challenge = session["challenge_wai"]

    resp, ephemeral_key, hardware_signature = wallet_entity.request_integrity_assertion(
        wallet_provider_id, challenge)
    session["ephemeral_key_tag"] = ephemeral_key.kid
    wallet_entity.context.wia_flow[ephemeral_key.kid]["integrity_assertion"] = resp[
        "integrity_assertion"]
    wallet_entity.context.wia_flow[ephemeral_key.kid]["hardware_signature"] = hardware_signature

    return render_template('integrity.html', integrity_response=resp)


@entity.route('/wallet_attestation_issuance')
def wai():
    return render_template('wallet_attestation_issuance.html')


@entity.route('/wallet_instance_request')
def wir():
    # This is where the attestation request is constructed and sent to the Wallet Provider.
    # And where the response is unpacked.
    wallet_entity = current_app.server["wallet"]
    wallet_provider_id = session["wallet_provider_id"]
    challenge = session["challenge_wai"]
    _wia_info = wallet_entity.context.wia_flow[session["ephemeral_key_tag"]]
    integrity_assertion = _wia_info["integrity_assertion"]
    hardware_signature = _wia_info["hardware_signature"]
    hardware_key_tag = wallet_entity.context.crypto_hardware_key.kid

    wallet_instance_attestation, war_payload = wallet_entity.request_wallet_instance_attestation(
        wallet_provider_id, challenge, session["ephemeral_key_tag"],
        integrity_assertion=integrity_assertion,
        hardware_signature=hardware_signature,
        crypto_hardware_key_tag=hardware_key_tag
    )

    _wia_info["wallet_instance_attestation"] = wallet_instance_attestation

    _jwt = JWT(key_jar=wallet_entity.keyjar)
    _jwt.msg_cls = WalletInstanceAttestationJWT
    _ass = _jwt.unpack(token=wallet_instance_attestation["assertion"])

    return render_template('wallet_instance_attestation_request.html',
                           request_args=war_payload,
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
        if not _metadata:  # Simple fix
            continue
        if "openid_credential_issuer" in _metadata:
            res.append(entity_id)
        res.extend(
            current_app.federation_entity.trawl(ta_id, entity_id,
                                                entity_type="openid_credential_issuer"))

    credential_issuers = res

    _oci = {}
    credential_type = "PersonIdentificationData"
    for pid in set(res):
        oci_metadata = current_app.federation_entity.get_verified_metadata(pid)
        # logger.info(json.dumps(oci_metadata, sort_keys=True, indent=4))
        for id, cs in oci_metadata['openid_credential_issuer'][
            "credential_configurations_supported"].items():
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
    parent = current_app.server["pid_eaa_consumer"]
    _actor = parent.get_consumer(pid_issuer)
    if _actor is None:
        actor = parent.new_consumer(pid_issuer)
    else:
        actor = _actor

    wallet_entity = current_app.server["wallet"]

    b64hash = hash_func(pid_issuer)
    _redirect_uri = f"https://127.0.0.1:5005/authz_cb/{b64hash}"
    session["redirect_uri"] = _redirect_uri

    _key_tag = session["ephemeral_key_tag"]
    _wia_flow = wallet_entity.context.wia_flow[_key_tag]

    request_args = {
        "authorization_details": [{
            "type": "openid_credential",
            "format": "vc+sd-jwt",
            "vct": "PersonIdentificationData"
        }],
        "response_type": "code",
        "client_id": _key_tag,
        "redirect_uri": _redirect_uri,
    }

    kwargs = {
        "state": rndstr(24),
        "behaviour_args": {
            "wallet_instance_attestation": _wia_flow["wallet_instance_attestation"]["assertion"],
            "client_assertion": _wia_flow["wallet_instance_attestation"]["assertion"]
        }
    }

    if "pushed_authorization" in actor.context.add_on:
        _metadata = current_app.federation_entity.get_verified_metadata(actor.context.issuer)
        if "pushed_authorization_request_endpoint" in _metadata["oauth_authorization_server"]:
            kwargs["behaviour_args"]["pushed_authorization_request_endpoint"] = _metadata[
                "oauth_authorization_server"]["pushed_authorization_request_endpoint"]

    _wia_flow["state"] = kwargs["state"]

    _service = actor.get_service("authorization")
    _service.certificate_issuer_id = pid_issuer

    req_info = _service.get_request_parameters(request_args, **kwargs)

    session["auth_req_uri"] = req_info['url']
    logger.info(f"Redirect to: {req_info['url']}")
    redir = redirect(req_info["url"])
    redir.status_code = 302
    return redir


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
                           # par_request=session["par_req"],
                           # auth_req_uri=session["auth_req_uri"],
                           response=request.args.to_dict())


@entity.route('/token')
def token():
    consumer = get_consumer(session["issuer"])

    wallet_entity = current_app.server["wallet"]
    _key_tag = session["ephemeral_key_tag"]
    _wia_flow = wallet_entity.context.wia_flow[_key_tag]

    _req_args = consumer.context.cstate.get_set(_wia_flow["state"],
                                                claim=["redirect_uri", "code", "nonce"])

    _args = {
        "audience": consumer.context.issuer,
        "thumbprint": _key_tag,
        "wallet_instance_attestation": _wia_flow["wallet_instance_attestation"]["assertion"],
        "signing_key": wallet_entity.get_ephemeral_key(_key_tag)
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
        "state": _wia_flow["state"]
    }

    # Just for display purposes
    _service = consumer.get_service("accesstoken")
    _metadata = current_app.federation_entity.get_verified_metadata(consumer.context.issuer)
    _args["endpoint"] = _metadata['oauth_authorization_server']['token_endpoint']
    req_info = _service.get_request_parameters(_request_args, **_args)

    # Real request
    resp = consumer.do_request(
        "accesstoken",
        request_args=_request_args,
        state=_wia_flow["state"],
        **_args
    )
    del req_info["request"]
    return render_template('token.html', request=req_info, response=resp)


@entity.route('/credential')
def credential():
    consumer = get_consumer(session["issuer"])

    trust_chains = get_verified_trust_chains(consumer, consumer.context.issuer)
    trust_chain = trust_chains[0]
    wallet_entity = current_app.server["wallet"]
    wallet_entity.keyjar = import_jwks(wallet_entity.keyjar,
                                       trust_chain.metadata["openid_credential_issuer"]["jwks"],
                                       consumer.context.issuer)

    # consumer.context.keyjar = wallet_entity.keyjar
    consumer.keyjar = wallet_entity.keyjar
    _key_tag = session["ephemeral_key_tag"]
    _wia_flow = wallet_entity.context.wia_flow[_key_tag]

    _req_args = consumer.context.cstate.get_set(_wia_flow["state"], claim=["access_token"])

    _request_args = {
        "format": "vc+sd-jwt"
    }

    _service = consumer.get_service("credential")
    req_info = _service.get_request_parameters(_request_args,
                                               access_token=_req_args["access_token"],
                                               state=_wia_flow["state"])

    resp = consumer.do_request(
        "credential",
        request_args=_request_args,
        access_token=_req_args["access_token"],
        state=_wia_flow["state"],
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
