import logging
from urllib.parse import urlencode

from idpyoidc.message.oauth2 import AccessTokenRequest
from idpyoidc.server.exception import NoSuchGrant
from idpyoidc.server.oidc.registration import random_client_id
from satosa.context import Context
from satosa.internal import InternalData

from satosa_openid4vci.core import ExtendedContext
from satosa_openid4vci.core.response import JsonResponse
from satosa_openid4vci.utils import IdpyOidcUtils

logger = logging.getLogger(__name__)

class IdpyOidcEndpoints(IdpyOidcUtils):
    """Handles all the openid4vci endpoints"""

    def jwks_endpoint(self, context: Context):
        """
        Construct the JWKS document (served at /jwks).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        return JsonResponse(self.jwks_public)

    def entity_configuration_endpoint(self, context: ExtendedContext):
        """
        Construct the Entity Configuration
        served at /.well-known/openid-federation.

        :param context: the current context
        :type context: satosa.context.Context
        :return: HTTP response to the client
        :rtype: satosa.response.Response
        """
        endpoint = self.app.server.endpoint["entity_configuration"]
        logger.info(f'Request at the "{endpoint.name}" endpoint')
        http_info = self._get_http_info(context)

        parse_req = endpoint.parse_request(
            context.request, http_info=http_info)
        proc_req = endpoint.process_request(parse_req, http_info=http_info)

        info = endpoint.do_response(request=context.request, **proc_req)
        return JsonResponse(info["response"])

    def authorization_endpoint(self, context: ExtendedContext):
        """
        OAuth2 / OIDC Authorization endpoint
        Checks client_id and handles the authorization request
        """
        self._log_request(context, "Authorization endpoint request")
        self._load_cdb(context)

        endpoint = self.app.server.endpoint["authorization"]
        self._get_http_info(context)
        internal_req = self._handle_authn_request(context, endpoint)
        if not isinstance(internal_req, InternalData):  # pragma: no cover
            return self.send_response(internal_req)

        return self.auth_req_callback_func(context, internal_req)

    def token_endpoint(self, context: ExtendedContext):
        """
        Handle token requests (served at /token).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        self._log_request(context, "Token endpoint request")
        endpoint = self.app.server.endpoint["token"]
        http_info = self._get_http_info(context)

        try:
            self._load_cdb(context)
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
        try:
            self._load_session(raw_request, endpoint, http_info)
        except NoSuchGrant:
            _response = JsonResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Not owner of token",
                },
                status="403",
            )
            return self.send_response(_response)

        # in token endpoint we cannot parse a request without having loaded cdb and session first
        parse_req = self._parse_request(endpoint, context, http_info=http_info)

        ec = endpoint.upstream_get("context")
        self._load_claims(ec)
        proc_req = self._process_request(endpoint, context, parse_req, http_info)
        # flush as soon as possible, otherwise in case of an exception it would be
        # stored in the object ... until a next .load would happen ...
        ec.userinfo.flush()

        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)
        elif isinstance(proc_req, TokenErrorResponse):
            return self.send_response(JsonResponse(proc_req.to_dict(), status="403"))

        # TODO: remove when migrate to idpy-oidc
        # PATCH https://github.com/UniversitaDellaCalabria/SATOSA-oidcop/issues/29
        if isinstance(proc_req["response_args"].get("scope", str), list):
            proc_req["response_args"]["scope"] = " ".join(
                proc_req["response_args"]["scope"]
            )
        # end PATCH

        # better return jwt or jwe here!
        self.store_session_to_db()
        response = JsonResponse(proc_req["response_args"])

        return self.send_response(response)

    def userinfo_endpoint(self, context: ExtendedContext):
        self._log_request(context, "Userinfo endpoint request")
        endpoint = self.app.server.endpoint["userinfo"]
        http_info = self._get_http_info(context)

        # everything depends on bearer access token here
        self._load_session({}, endpoint, http_info)

        # not load the client from the session using the bearer token
        if self.dump_sessions():
            # load cdb from authz bearer token
            try:
                self._load_cdb(context)
            except Exception:
                logger.warning(
                    f"Userinfo endpoint request without any loadable client"
                )
                return self.send_response(
                    JsonResponse(
                        {"error": "invalid_client", "error_description": "<client not found>"},
                        status="403",
                    )
                )
        else:
            logger.warning(
                f"Userinfo endpoint request without any loadable sessions"
            )
            return self.send_response(
                JsonResponse(
                    {"error": "invalid_token", "error_description": "<no loadable session>"},
                    status="403",
                )
            )

        try:
            parse_req = self._parse_request(
                endpoint, context, http_info=http_info
            )
        except KeyError:
            return self.send_response(
                JsonResponse(
                    {"error": "invalid_token", "error_description": "<TOKEN>"},
                    status="403",
                )
            )

        ec = endpoint.upstream_get("context")
        self._load_claims(ec)
        proc_req = self._process_request(
            endpoint, context, parse_req, http_info)
        # flush as soon as possible, otherwise in case of an exception it would be
        # stored in the object ... until a next .load would happen ...
        ec.userinfo.flush()

        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)
        elif "error" in proc_req or "error" in proc_req.get("response_args", {}):
            return self.send_response(
                JsonResponse(
                    proc_req["response_args"]
                    if "response_args" in proc_req
                    else proc_req.to_dict(),
                    status="403",
                )
            )

        # better return jwt or jwe here!
        response = JsonResponse(proc_req["response_args"])

        self.store_session_to_db()
        return self.send_response(response)

    def _load_claims(self, endpoint_context):
        claims = {}
        sman = endpoint_context.session_manager
        for k, v in sman.dump()["db"].items():
            if v[0] == "idpyoidc.server.session.grant.Grant":
                sid = k
                claims = self.app.storage.get_claims_from_sid(sid)
                break
            else:  # pragma: no cover
                continue

        if not claims:
            logger.warning(
                "Can't find any suitable sid/claims from stored session"
            )

        # That's a patchy runtime definition of userinfo db configuration
        endpoint_context.userinfo.load(claims)

    def registration_read_endpoint(self, context: ExtendedContext):
        """
        The Client Configuration Endpoint is an OAuth 2.0 Protected Resource
        that MAY be provisioned by the server for a specific Client to be able
        to view its registered information.

        The Client MUST use its Registration Access Token in all calls
        to this endpoint as an OAuth 2.0 Bearer Token
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        self._log_request(context, "Client Registration Read endpoint request")
        self._load_cdb(context)
        http_info = self._get_http_info(context)
        endpoint = self.app.server.endpoint["registration_read"]
        parse_req = self._parse_request(
            endpoint, context, http_info=http_info)
        proc_req = self._process_request(
            endpoint, context, parse_req, http_info)
        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)
        # better return jwt or jwe here!
        response = JsonResponse(proc_req["response_args"].to_dict())
        return self.send_response(response)

    def registration_endpoint(self, context: ExtendedContext):
        """
        Handle the OIDC dynamic client registration.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        self._log_request(context, "Client Registration endpoint request")
        http_info = self._get_http_info(context)
        endpoint = self.app.server.endpoint["registration"]
        parse_req = self._parse_request(
            endpoint, context, http_info=http_info)
        proc_req = self._process_request(
            endpoint, context, parse_req, http_info)
        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)
        # store client to storage
        client_data = context.request
        client_data["client_id"] = random_client_id(
            reserved=self.get_registered_client_ids()
        )
        self.store_client(client_data)
        return JsonResponse(client_data)

    def introspection_endpoint(self, context: ExtendedContext):
        self._log_request(context, "Token Introspection endpoint request")
        endpoint = self.app.server.endpoint["introspection"]
        http_info = self._get_http_info(context)

        self._load_cdb(context)
        self._load_session(context.request, endpoint, http_info)
        parse_req = self._parse_request(
            endpoint, context, http_info=http_info)
        proc_req = self._process_request(
            endpoint, context, parse_req, http_info)
        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)

        # better return jwt or jwe here!
        response = JsonResponse(proc_req["response_args"].to_dict())

        self._flush_endpoint_context_memory()
        return self.send_response(response)

