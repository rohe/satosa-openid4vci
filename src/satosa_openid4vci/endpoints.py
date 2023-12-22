import logging
from urllib.parse import urlencode

from idpyoidc.message.oauth2 import AccessTokenRequest
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server.exception import NoSuchGrant
from idpyoidc.server.exception import UnknownClient
from openid4v.message import auth_detail_list_deser
from openid4v.message import AuthorizationDetail
from openid4v.message import AuthorizationRequest
from satosa.context import Context
from satosa_openid4vci.core import ExtendedContext
from satosa_openid4vci.core.response import JsonResponse
from satosa_openid4vci.core.response import JWSResponse
from satosa_openid4vci.endpoint_wrapper.authorization import VCIAuthorization
from satosa_openid4vci.utils import Openid4VCIUtils

logger = logging.getLogger(__name__)


class Openid4VCIEndpoints(Openid4VCIUtils):
    """Handles all the Entity endpoints"""

    def __init__(self, app, auth_req_callback_func, converter):  # pragma: no cover
        Openid4VCIUtils.__init__(app)
        self.endpoint_wrapper = {
            "authorization": VCIAuthorization(self.app, auth_req_callback_func, converter)
        }

    def jwks_endpoint(self, context: Context):
        """
        Construct the JWKS document (served at /jwks).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        logger.debug("At the JWKS endpoint")
        jwks = self.app.server["openid_credential_issuer"].keyjar.export_jwks()
        return JsonResponse(jwks)

    def _request_setup(self, context: ExtendedContext, entity_type: str, endpoint: str):
        _entity_type = self.app.server[entity_type]
        endpoint = _entity_type.get_endpoint(endpoint)
        logger.debug(20 * "=" + f'Request at the "{endpoint.name}" endpoint' + 20 * "-")
        logger.debug(f"endpoint={endpoint}")
        http_info = self.get_http_info(context)

        return {
            "http_info": http_info,
            "endpoint": endpoint,
            "entity_type": _entity_type
        }

    def entity_configuration_endpoint(self, context: ExtendedContext):
        """
        Construct the Entity Configuration
        served at /.well-known/openid-federation.

        :param context: the current context
        :type context: satosa.context.Context
        :return: HTTP response to the client
        :rtype: satosa.response.Response
        """
        _env = self._request_setup(context, entity_type="federation_entity",
                                   endpoint="entity_configuration")

        parsed_req = self.parse_request(_env["endpoint"], context.request,
                                        http_info=_env["http_info"])
        proc_req = _env["endpoint"].process_request(parsed_req, http_info=_env["http_info"])

        info = _env["endpoint"].do_response(request=parsed_req, **proc_req)
        return JWSResponse(info["response"], content="application/entity-statement+jwt")

    def authorization_endpoint(self, context: ExtendedContext):
        """
        OAuth2 / OIDC Authorization endpoint
        Checks client_id and handles the authorization request
        """
        logger.debug("At the Authorization Endpoint")
        _entity_type = self.app.server["openid_credential_issuer"]
        _entity_type.persistence.restore_pushed_authorization()
        _fed_entity = self.app.server["federation_entity"]
        _fed_entity.persistence.restore_state()

        resp = self.endpoint_wrapper["authorization"](context)

        _fed_entity.persistence.store_state()

        return resp

    def token_endpoint(self, context: ExtendedContext):
        """
        Handle token requests (served at /token).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        _env = self._request_setup(context, "openid_credential_issuer", "token")

        try:
            self.load_cdb(context)
        except UnknownClient:
            return self.send_response(
                JsonResponse(
                    {
                        "error": "unauthorized_client",
                        "error_description": "unknown client",
                    }
                )
            )

        raw_request = AccessTokenRequest().from_urlencoded(urlencode(context.request))

        _entity_type = _env["entity_type"]
        # in token endpoint we cannot parse a request without having loaded cdb and session first
        try:
            _entity_type.persistence.restore_state(raw_request, _env["http_info"])
        except NoSuchGrant:
            _response = JsonResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Not owner of token",
                },
                status="403",
            )
            return self.send_response(_response)

        parse_req = self.parse_request(_env["endpoint"], context.request, http_info=_env["http_info"])
        ec = _env["endpoint"].upstream_get("context")
        _entity_type.load_all_claims()
        proc_req = self.process_request(_env["endpoint"], context, parse_req, _env["http_info"])
        # flush as soon as possible, otherwise in case of an exception it would be
        # stored in the object ... until a next .load would happen ...
        ec.userinfo.flush()

        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)
        elif isinstance(proc_req, TokenErrorResponse):
            return self.send_response(JsonResponse(proc_req.to_dict(), status="403"))

        if isinstance(proc_req["response_args"].get("scope", str), list):
            proc_req["response_args"]["scope"] = " ".join(
                proc_req["response_args"]["scope"]
            )

        # should only be one client in the client db
        _client_id = list(_entity_type.context.cdb.keys())[0]
        _entity_type.persistence.store_state(_client_id)

        # better return jwt or jwe here!
        response = JsonResponse(proc_req["response_args"])
        return self.send_response(response)

    def credential_endpoint(self, context: ExtendedContext):
        _env = self._request_setup(context, "openid_credential_issuer", "credential")
        _env["entity_type"].persistence.restore_state(context.request, _env["http_info"])

        parse_req = self.parse_request(_env["endpoint"], context.request, http_info=_env["http_info"])
        proc_req = self.process_request(_env["endpoint"], context.request, parse_req, _env["http_info"])
        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)

        # The only thing that should have changed
        _env["entity_type"].persistence.store_pushed_authorization()

        response = JsonResponse(proc_req["response_args"].to_dict())
        return self.send_response(response)

    def pushed_authorization_endpoint(self, context: ExtendedContext):
        _env = self._request_setup(context, "openid_credential_issuer", "pushed_authorization")
        _env["entity_type"].persistence.restore_state(context.request, _env["http_info"])

        _env["endpoint"].request_format = "dict"
        _env["endpoint"].request_cls = AuthorizationRequest

        # This is not how it should be done, but it has to be done.
        logger.debug(f"Before adl: {context.request['authorization_details']}")
        adl = auth_detail_list_deser(context.request["authorization_details"], sformat="urlencoded")
        logger.debug(f"adl: {adl} {type(adl)}")
        context.request["authorization_details"] = [v.to_dict() for v in adl]

        logger.debug(f"Incoming request: {context.request}")
        parse_req = self.parse_request(_env["endpoint"], context.request, http_info=_env["http_info"])
        logger.debug(f"Parsed request: {parse_req} {type(parse_req)}")
        logger.debug(f"ad type: {type(context.request['authorization_details'][0])}")
        logger.debug(f"cd type: {type(context.request['authorization_details'][0]['credential_definition'])}")
        parse_req["authorization_details"] = [AuthorizationDetail(**item) for item in parse_req[
            "authorization_details"]]
        proc_req = self.process_request(_env["endpoint"], context, parse_req, _env["http_info"])
        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)

        # The only thing that should have changed on the application side
        _env["entity_type"].persistence.store_client_info(parse_req["client_id"])
        _env["entity_type"].persistence.store_pushed_authorization()
        # Also on the federation side
        _fed_entity = self.app.server["federation_entity"]
        _fed_entity.persistence.store_state()

        logger.debug(f"PAR response: {proc_req}")
        response = JsonResponse(proc_req["http_response"])
        return self.send_response(response)
