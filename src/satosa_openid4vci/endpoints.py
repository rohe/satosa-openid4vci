import logging

from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from openid4v.message import AuthorizationDetail
from openid4v.message import AuthorizationRequest
from satosa.context import Context
from satosa_idpyop.core import ExtendedContext
from satosa_idpyop.core.response import JWSResponse
from satosa_idpyop.core.response import JsonResponse
from satosa_idpyop.endpoint_wrapper.token import TokenEndpointWrapper
from satosa_idpyop.utils import get_http_info

from satosa_openid4vci.endpoint_wrapper.authorization import AuthorizationEndpointWrapper
from satosa_openid4vci.endpoint_wrapper.credential import CredentialEndpointWrapper
from satosa_openid4vci.utils import Openid4VCIUtils

logger = logging.getLogger(__name__)


class Openid4VCIEndpoints(Openid4VCIUtils):
    """Handles all the Entity endpoints"""

    def __init__(self, app, auth_req_callback_func, converter):  # pragma: no cover
        Openid4VCIUtils.__init__(app)
        self.endpoint_wrapper = {}

        setup = {
            "openid_credential_issuer": {"credential": CredentialEndpointWrapper},
            "oauth_authorization_server": {"authorization": AuthorizationEndpointWrapper,
                                           "token": TokenEndpointWrapper}
        }
        for guise, endpoints in setup.items():
            _unit_get = self.app.server[guise].unit_get
            for endpoint_name, wrapper in endpoints.items():
                _endpoint = self.app.server[guise].get_endpoint(endpoint_name)
                if endpoint_name == "authorization":
                    _auth_req_callback_func = auth_req_callback_func
                else:
                    _auth_req_callback_func = None
                self.endpoint_wrapper[endpoint_name] = wrapper(
                    upstream_get=_unit_get, endpoint=_endpoint,
                    auth_req_callback_func=_auth_req_callback_func,
                    converter=converter)

    def jwks_endpoint(self, context: Context):
        """
        Construct the JWKS document (served at /jwks).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        logger.debug("At the JWKS endpoint")
        jwks = self.app.server["oauth_authorization_server"].context.keyjar.export_jwks("")
        return JsonResponse(jwks)

    def _request_setup(self, context: ExtendedContext, entity_type: str, endpoint: str):
        _guise = self.app.server[entity_type]
        endpoint = _guise.get_endpoint(endpoint)
        logger.debug(20 * "=" + f'Request at the "{endpoint.name}" endpoint' + 20 * "-")
        logger.debug(f"endpoint={endpoint}")
        http_info = get_http_info(context)
        logger.debug(f"http_info: {http_info}")

        return {
            "http_info": http_info,
            "endpoint": endpoint,
            "entity_type": _guise
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
        logger.debug(
            f"OAuth servers provider_info: "
            f"{self.app.server['oauth_authorization_server'].context.provider_info}")

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
        logger.debug(20 * "=" + f'Request at the "Authorization" endpoint' + 20 * "-")
        _guise = self.app.server['oauth_authorization_server']
        _guise.persistence.restore_pushed_authorization()
        _fed_entity = self.app.server["federation_entity"]
        _fed_entity.persistence.restore_state()

        logger.debug(f"Default target backend: {self.app.default_target_backend}")
        context.target_backend = self.app.default_target_backend

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
        logger.debug("At the Token Endpoint")
        logger.debug(f"Request: {context.request}")
        response = self.endpoint_wrapper["token"](context)

        return self.send_response(response)

    def credential_endpoint(self, context: ExtendedContext):
        logger.debug("At the Credential Endpoint")

        response = self.endpoint_wrapper["credential"](context)

        return self.send_response(response)

    def pushed_authorization_endpoint(self, context: ExtendedContext):
        _env = self._request_setup(context, "oauth_authorization_server",
                                   "pushed_authorization")
        _env["entity_type"].persistence.restore_state(context.request, _env["http_info"])

        _env["endpoint"].request_format = "dict"
        _env["endpoint"].request_cls = AuthorizationRequest

        logger.debug(f"Request: {context.request}")
        if "request" in context.request:
            _keyjar = _env["endpoint"].upstream_get("attribute", "keyjar")
            _jws = factory(context.request["request"])
            if not _jws:
                logger.warning("request not a signed JWT")
                # raise ValueError("RequestObject not a signed JWT")
                response = JsonResponse(
                    {
                        "error": "invalid_request",
                        "error_description": f"Request object not a signed JWT",
                    },
                    status="403",
                )
                return self.send_response(response)
            else:
                _iss = _jws.jwt.payload()["iss"]
                if _iss not in _keyjar:
                    logger.debug(f"Unregistered client '{_iss}'")
                    # do automatic/semi-automatic registration
                else:
                    _jwt = JWT(key_jar=_keyjar)
                    _request = _jwt.unpack(context.request["request"])
                    del context.request["request"]
                    context.request.update(_request)

        logger.debug(f"request: {context.request}")

        # This is not how it should be done, but it has to be done.
        if "authorization_details" in context.request:
            logger.debug("Need to deal with 'authorization_details'")
            if context.request["authorization_details"].startswith("[") and context.request[
                "authorization_details"].endswith("]"):
                _ads = context.request["authorization_details"][1:-1].split(",")
                _list = []
                for _url_ad in _ads:
                    _url_ad = _url_ad[1:-1]
                    _item = AuthorizationDetail().from_urlencoded(_url_ad)
                    _list.append(_item.to_dict())
                context.request["authorization_details"] = _list

        logger.debug(f"Incoming request: {context.request}")
        parse_req = self.parse_request(_env["endpoint"], context.request,
                                       http_info=_env["http_info"])
        logger.debug(f"Parsed request: {parse_req} {type(parse_req)}")
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
        response = JsonResponse(proc_req["response_args"])
        return self.send_response(response)
