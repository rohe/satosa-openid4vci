"""
The OpenID4vci (Credential Issuer) frontend module for the satosa proxy
"""
import base64
import logging
import os
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

from idpyoidc.message import Message
from idpyoidc.message.oauth2 import AuthorizationErrorResponse
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.server.authn_event import create_authn_event
import satosa
from satosa.context import Context
from satosa.response import SeeOther
from satosa_idpyop.core import ExtendedContext
from satosa_idpyop.core.claims import combine_claim_values
from satosa_idpyop.core.response import JsonResponse
from satosa_idpyop.utils import combine_client_subject_id
from satosa_idpyop.utils import get_http_info

from .endpoints import Openid4VCIEndpoints

try:
    from satosa.context import add_prompt_to_context
except ImportError:
    # TODO: remove after https://github.com/IdentityPython/SATOSA/pull/419 is merged
    def add_prompt_to_context(*args, **kwargs):
        pass
from satosa.frontends.base import FrontendModule

from satosa_idpyop.core.application import idpy_oidc_application as idpy_oidc_app

logger = logging.getLogger(__name__)

IGNORED_HEADERS = ["cookie", "user-agent"]


class OpenID4VCIFrontend(FrontendModule, Openid4VCIEndpoints):
    """
    OpenID Connect frontend module based on idpy-oidc
    """

    def __init__(self,
                 auth_req_callback_func,
                 internal_attributes,
                 conf,
                 base_url,
                 name
                 ):
        FrontendModule.__init__(self, auth_req_callback_func, internal_attributes, base_url, name)
        self.app = idpy_oidc_app(conf)
        self.app.server.frontend_name = name
        Openid4VCIEndpoints.__init__(self, self.app, auth_req_callback_func, self.converter)
        # registered endpoints will be filled by self.register_endpoints
        self.endpoints = None
        federation_persistence = getattr(self.app.federation_entity, "persistence", None)
        if federation_persistence:
            federation_persistence.store_state()
        oauth_persistence = getattr(self.app.oauth_authorization_server, "persistence", None)
        if oauth_persistence:
            oauth_persistence.store_state()

    def oci_jwks_endpoint(self, context: Context):
        """
        Construct the JWKS document (served at /jwks).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        logger.debug("At the OCI JWKS endpoint")
        jwks = self.app.server["openid_credential_issuer"].context.keyjar.export_jwks("")
        return JsonResponse(jwks)

    def oas_jwks_endpoint(self, context: Context):
        """
        Construct the JWKS document (served at /jwks).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        logger.debug("At the OAS JWKS endpoint")
        jwks = self.app.server["oauth_authorization_server"].context.keyjar.export_jwks("")
        return JsonResponse(jwks)

    def register_endpoints(self, *kwargs):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        url_map = []
        for entity_type, item in self.app.server.items():
            if entity_type == "federation_entity":
                for k, v in item.server.endpoint.items():
                    url_map.append((f"^{v.endpoint_path}", getattr(self, f"{k}_endpoint")))
            else:
                for k, v in item.endpoint.items():
                    url_map.append((f"^{v.endpoint_path}", getattr(self, f"{k}_endpoint")))

        # add jwks.json web path
        uri_path = self.app.server["oauth_authorization_server"].config["key_conf"]["uri_path"]
        url_map.append((f"^{uri_path}", self.oas_jwks_endpoint))
        # uri_path = self.app.server["openid_credential_issuer"].config["key_conf"]["uri_path"]
        # url_map.append((f"^{uri_path}", self.oci_jwks_endpoint))

        logger.debug(f"Loaded Credential Issuer endpoints: {url_map}")
        self.endpoints = url_map
        return url_map

    def _handle_backend_response(self, context: ExtendedContext, internal_resp):
        """
        Called by handle_authn_response, once a backend done its work
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :param internal_resp: satosa internal data
        :type internal_resp: satosa.internal.InternalData
        :return: HTTP response to the client
        """
        logger.debug(f"Internal_resp: {internal_resp}")

        http_info = get_http_info(context)
        logger.debug(f"context.state: {context.state.keys()}")
        orig_req = context.state[self.name]["oidc_request"]

        # _entity_type = self.app.server["openid_credential_issuer"]
        _entity_type = self.app.server["oauth_authorization_server"]
        if isinstance(orig_req, str):
            # urlencoded
            orig_req = Message().from_urlencoded(orig_req)

        _entity_type.persistence.restore_state(orig_req, http_info)
        endpoint = _entity_type.get_endpoint("authorization")
        # have to look up the original authorization request in the PAR db
        _ec = endpoint.upstream_get("context")
        _entity_type.persistence.restore_pushed_authorization()
        logger.debug(f"PAR_db: {list(_ec.par_db.keys())}")
        parse_req = None
        if _ec.par_db:
            _req_uri = orig_req.get("request_uri", "")
            if _req_uri:
                parse_req = _ec.par_db.get(_req_uri, None)
        #
        if not parse_req:
            parse_req = orig_req
        client_id = parse_req["client_id"]

        # sub = internal_resp.subject_id
        logger.info(f"Response attributes = {internal_resp.attributes}")
        # Which attribute/-s to use should be configurable
        sub = internal_resp.subject_id
        # sub = internal_resp.attributes.get("mail")
        if sub and isinstance(sub, list):
            sub = sub[0]
        if not sub:
            sub = internal_resp.subject_id

        authn_event = create_authn_event(
            uid=sub,
            salt=base64.b64encode(os.urandom(self.app.salt_size)).decode(),
            authn_info=internal_resp.auth_info.auth_class_ref,
            # TODO: authn_time=datetime.fromisoformat(
            #  internal_resp.auth_info.timestamp).timestamp(),
        )

        session_manager = _ec.session_manager
        client_info = _entity_type.persistence.restore_client_info(client_id)
        client_subject_type = client_info.get("subject_type", "public")

        scopes = parse_req.get("scopes", [])

        _session_id = session_manager.create_session(
            authn_event=authn_event,
            auth_req=parse_req,
            user_id=sub,
            client_id=client_id,
            sub_type=client_subject_type,
            scopes=scopes
        )

        try:
            # _args is a dict that contains:
            #  - idpyoidc.message.oidc.AuthorizationResponse
            #  - session_id
            #  - cookie (only need for logout -> not yet supported by Satosa)
            _args = endpoint.authz_part2(
                user=sub,
                session_id=_session_id,
                request=parse_req,
                authn_event=authn_event,
            )
        except ValueError as excp:  # pragma: no cover
            # TODO - cover with unit test and add some satosa logging ...
            return self.handle_error(excp=excp)
        except Exception as excp:  # pragma: no cover
            return self.handle_error(excp=excp)

        logger.debug(f"authz_part2 args: {_args}")

        if isinstance(_args, ResponseMessage) and "error" in _args:  # pragma: no cover
            return self.send_response(JsonResponse(_args, status="403"))
        elif isinstance(_args.get("response_args"), AuthorizationErrorResponse):  # pragma: no cover
            rargs = _args.get("response_args")
            logger.error(rargs)
            response = JsonResponse(rargs.to_json(), status="403")
            return self.send_response(response)

        kwargs = {
            "fragment_enc": _args.get("fragment_enc", None),
            "return_uri": _args.get("return_uri")
        }

        info = endpoint.do_response(response_args=_args.get("response_args"), request=parse_req,
                                    **kwargs)

        logger.debug(f"Response from OCI: {info}")

        info_response = info["response"]
        _response_placement = info.get(
            "response_placement", endpoint.response_placement
        )
        if _response_placement == "url":
            data = _args["response_args"].to_dict()
            url_components = urlparse(info_response)
            original_params = parse_qs(url_components.query)
            merged_params = {**original_params, **data}
            updated_query = urlencode(merged_params, doseq=True)
            redirect_url = url_components._replace(query=updated_query).geturl()
            logger.debug(f"Redirect to: {redirect_url}")
            resp = SeeOther(redirect_url)
        else:  # pragma: no cover
            raise NotImplementedError()

        return resp

    def handle_authn_response(self, context: ExtendedContext, internal_resp):
        """
        See super class method satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_resp: satosa.internal.InternalData
        :rtype satosa.response.SeeOther
        """
        _claims = self.converter.from_internal("openid", internal_resp.attributes)
        claims = {k: v for k, v in _claims.items() if v}
        combined_claims = dict([i for i in combine_claim_values(claims.items())])

        response = self._handle_backend_response(context, internal_resp)

        # store oidc session with user claims
        client_id = ""
        if context.request:
            client_id = context.request.get("client_id")
        if not client_id:
            oidc_req = context.state[self.name]["oidc_request"]
            client_id = oidc_req["client_id"]

        _entity_type = self.app.server["oauth_authorization_server"]
        client_subject_id = combine_client_subject_id(client_id, internal_resp.subject_id)
        _entity_type.persistence.store_claims(combined_claims, client_subject_id)
        _entity_type.persistence.store_state(client_id)
        return self.send_response(response)
