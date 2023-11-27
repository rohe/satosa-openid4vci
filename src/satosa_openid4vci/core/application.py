import logging
import os

from idpyoidc.server import Server
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.util import execute

# from idpyoidc.server.util import importer

folder = os.path.dirname(os.path.realpath(__file__))
logger = logging.getLogger(__name__)


def oidc_provider_init_app(config, name="idpy_oidc", **kwargs):
    name = name or __name__
    app = type("IdpyOidcApp", (object,), {"srv_config": config})
    app.server = Server(config, cwd=folder)
    return app


def idpy_oidc_application(conf: dict):
    domain = getattr(conf, "domain", None)
    config = OPConfiguration(conf=conf["op"]["server_info"], domain=domain)
    app = oidc_provider_init_app(config)

    # app customs
    app.default_target_backend = conf.get("default_target_backend")
    app.salt_size = conf.get("salt_size", 8)

    app.storage = execute(conf["storage"])
    return app