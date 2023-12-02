"""
The OpenID4vci (Credential Issuer) frontend module for the satosa proxy
"""
import logging

import satosa

from .endpoint_wrapper.authorization import VCIAuthorization
from .endpoints import Openid4VCIEndpoints

try:
    from satosa.context import add_prompt_to_context
except ImportError:
    # TODO: remove after https://github.com/IdentityPython/SATOSA/pull/419 is merged
    def add_prompt_to_context(*args, **kwargs):
        pass
from satosa.frontends.base import FrontendModule

from .core.application import idpy_oidc_application as idpy_oidc_app

logger = logging.getLogger(__name__)

IGNORED_HEADERS = ["cookie", "user-agent"]


class OpenID4VCIFrontend(FrontendModule, Openid4VCIEndpoints):
    """
    OpenID Connect frontend module based on idpy oidcop
    """

    def __init__(self,
                 auth_req_callback_func,
                 internal_attributes,
                 conf,
                 base_url,
                 name
    ):
        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)
        self.app = idpy_oidc_app(conf)


        # registered endpoints will be filled by self.register_endpoints
        self.endpoints = None

    def register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        url_map = []
        for entity_type, item in self.app.server.items():
            if entity_type == "federation_entity":
                for k,v in item.server.endpoint.items():
                    url_map.append((v.endpoint_path, getattr(self, f"{k}_endpoint")))
            else:
                for k,v in item.endpoint.items():
                    url_map.append((v.endpoint_path, getattr(self, f"{k}_endpoint")))

        # add jwks.json webpath
        uri_path = self.app.server["openid_provider"].config["key_conf"]["uri_path"]
        url_map.append((uri_path, self.jwks_endpoint))

        logger.debug(f"Loaded OIDC Provider endpoints: {url_map}")
        self.endpoints = url_map
        return url_map
