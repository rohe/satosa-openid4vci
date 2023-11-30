import logging
import os

from fedservice.utils import make_federation_combo
from idpyoidc.server import Server
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.util import execute

# from idpyoidc.server.util import importer

folder = os.path.dirname(os.path.realpath(__file__))
logger = logging.getLogger(__name__)


def oidc_provider_init_app(config, domain, name="idpy_oidc", **kwargs):
    name = name or __name__
    app = type("IdpyOidcApp", (object,), {"entity_config": config})
    app.server = make_federation_combo(**config)
    for entity_type in app.server.keys():
        setattr(app, entity_type, app.server[entity_type])

    return app


def idpy_oidc_application(conf: dict):
    domain = getattr(conf, "domain", None)
    config = conf["op"]["server_info"]
    app = oidc_provider_init_app(config, domain)

    # app customs
    app.default_target_backend = conf.get("default_target_backend")
    app.salt_size = conf.get("salt_size", 8)

    return app
