from openid4v.message import AuthorizationRequest
from satosa_idpyop.endpoint_wrapper.authorization import handle_authorization_details_decoding


def test_authz_req_url():
    _req = {'authorization_details': "['type=openid_credential&credential_configuration_id=PersonIdentificationData']",
            'response_type': 'code',
            'client_id': 'NWljZEl1RmJKRFBHeHVKYjJsanlteDgweTZQVWlOVUF0a1RlOFQ4XzMzaw',
            'redirect_uri': 'https://127.0.0.1:5005/authz_cb/qoY_THoYZlRRJXth_314qanSMpn_9MFe1uGV7TF5K4M',
            'state': '_paE9GCZ-4aj01AKB0mez9VOYF7PzNzn',
            'code_challenge': 'pnPm2mMo_sSs7LPLJq-mdYbgOLXLT5YcIbFgcl_twnI',
            'code_challenge_method': 'S256'}

    handle_authorization_details_decoding(_req)

    req = AuthorizationRequest(**_req)
    assert req
