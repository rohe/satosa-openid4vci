"""
The OpenID4vci (Credential Issuer) frontend module for the satosa proxy
"""
import logging

from cryptojwt import KeyJar
from idpyoidc.message.oidc import AuthnToken
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.exception import InvalidClient
from idpyoidc.server.exception import UnAuthorizedClient
from idpyoidc.server.exception import UnknownClient
from satosa.context import Context

from .core import ExtendedContext
from .core.persistence import Persistence

try:
    from satosa.context import add_prompt_to_context
except ImportError:
    # TODO: remove after https://github.com/IdentityPython/SATOSA/pull/419 is merged
    def add_prompt_to_context(*args, **kwargs):
        pass
import satosa.logging_util as lu

from .core.response import JsonResponse

logger = logging.getLogger(__name__)

IGNORED_HEADERS = ["cookie", "user-agent"]


class IdpyOidcUtils(Persistence):
    """
    Interoperability class between satosa and idpy-oidc
    """

    def __init__(self):  # pragma: no cover
        Persistence.__init__(self)
        self.jwks_public = {}
        self.app = None

    # not sure I'll need this
    def _get_http_info(self, context: ExtendedContext):
        """
        aligns parameters for oidcop interoperability needs
        """
        http_info = {"headers": {}}

        if getattr(context, "http_info", None):
            http_info = {
                "headers": {
                    k.lower(): v
                    for k, v in context.http_info.items()
                    if k not in IGNORED_HEADERS
                },
                "method": context.request_method,
                "url": context.request_uri,
            }

        # for token and userinfo endpoint ... but also for authz endpoint if needed
        if getattr(context, "request_authorization", None):
            http_info["headers"].update(
                {"authorization": context.request_authorization}
            )

        context.http_info = http_info

        return http_info

    def _parse_request(
            self, endpoint, context: ExtendedContext, http_info: dict = None
    ):
        """
        Returns a parsed OAuth2/OIDC request,
        used by Authorization, Token, Userinfo and Introspection endpoints views
        """
        http_info = http_info or self._get_http_info(context)
        try:
            parse_req = endpoint.parse_request(
                context.request, http_info=http_info,
            )
        except (
                InvalidClient,
                UnknownClient,
                UnAuthorizedClient,
                ClientAuthenticationError,
        ) as err:
            logger.error(err)
            response = JsonResponse(
                {"error": "unauthorized_client", "error_description": str(err)},
                status="403",
            )
            return self.send_response(response)
        return parse_req

    def _process_request(self, endpoint, context: Context, parse_req, http_info):
        """
        Processes an OAuth2/OIDC request
        used by Authorization, Token, Userinfo and Introspection endpoint views
        """
        if isinstance(parse_req, JsonResponse):
            return self.send_response(parse_req)

        # do not lety idpy-oidc handle prompt, handle it here instead
        prompt_arg = parse_req.pop("prompt", None)
        if prompt_arg:
            add_prompt_to_context(context, " ".join(prompt_arg) if isinstance(prompt_arg,
                                                                              list) else prompt_arg)

        # save ACRs
        acr_values = parse_req.pop("acr_values", None)
        if acr_values:
            acr_values = acr_values if isinstance(acr_values, list) else acr_values.split(" ")
            context.decorate(Context.KEY_AUTHN_CONTEXT_CLASS_REF, acr_values)
            context.state[Context.KEY_AUTHN_CONTEXT_CLASS_REF] = acr_values

        try:
            proc_req = endpoint.process_request(
                parse_req, http_info=http_info)
            return proc_req
        except Exception as err:  # pragma: no cover
            logger.error(
                f"In endpoint.process_request: {parse_req.__dict__} - {err}")
            response = JsonResponse(
                {
                    "error": "invalid_request",
                    "error_description": "request cannot be processed",
                },
                status="403",
            )
            return self.send_response(response)

    def _log_request(self, context: ExtendedContext, msg: str, level: str = "info"):
        _msg = f"{msg}: {context.request}"
        logline = lu.LOG_FMT.format(
            id=lu.get_session_id(context.state), message=_msg)
        getattr(logger, level)(logline)

    def handle_error(
            self, msg: str = None, excp: Exception = None, status: str = "403"
    ):  # pragma: no cover
        _msg = f'Something went wrong ... {excp or ""}'
        msg = msg or _msg
        logger.error(msg)
        response = JsonResponse(msg, status=status)
        return self.send_response(response)

    def send_response(self, response):
        self._flush_endpoint_context_memory()
        return response

    def _load_cdb(self, context: ExtendedContext, client_id: str = None) -> dict:
        """
        gets client_id from local storage and updates the client DB
        """
        if client_id:
            client_id = client_id
        elif context.request and isinstance(context.request, dict):
            client_id = context.request.get("client_id")

        _ec = self.app.server.context

        if client_id:
            client = self.get_client_by_id(client_id)
        elif "Basic " in getattr(context, "request_authorization", ""):
            # here even for introspection endpoint
            client = self.get_client_by_basic_auth(context.request_authorization) or {}
            client_id = client.get("client_id")
        elif context.request and context.request.get(
                "client_assertion"
        ):  # pragma: no cover
            # this is not a validation just a client detection
            # validation is demanded later to oidcop parse_request

            ####
            # WARNING: private_key_jwt can't be supported in SATOSA directly to token endpoint
            # because the user MUST always pass through the authorization endpoint
            ####
            token = AuthnToken().from_jwt(
                txt=context.request["client_assertion"],
                keyjar=KeyJar(),  # keyless keyjar
                verify=False,  # otherwise keyjar would contain the issuer key
            )
            client_id = token.get("iss")
            client = self.get_client_by_id(client_id)

        elif "Bearer " in getattr(context, "request_authorization", ""):
            client = (
                    self.get_client_by_bearer_token(
                        context.request_authorization)
                    or {}
            )
            client_id = client.get("client_id")

        else:  # pragma: no cover
            _ec.cdb = {}
            _msg = f"Client {client_id} not found!"
            logger.warning(_msg)
            raise InvalidClient(_msg)

        if client:
            _ec.cdb = {client_id: client}
            logger.debug(
                f"Loaded oidcop client from {self.app.storage}: {client}")
        else:  # pragma: no cover
            logger.info(f'Cannot find "{client_id}" in client DB')
            raise UnknownClient(client_id)

        # TODO - consider to handle also basic auth for clients ...
        # BUT specs are against!
        # https://openid.net/specs/openid-connect-registration-1_0.html#ReadRequest
        _rat = client.get("registration_access_token")
        if _rat:
            _ec.registration_access_token[_rat] = client["client_id"]
        else:
            _ec.registration_access_token = {}
        return client
