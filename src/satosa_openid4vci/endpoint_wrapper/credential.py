import logging

from idpyoidc.message import Message
from satosa_idpyop.core.response import JsonResponse
from satosa_idpyop.endpoint_wrapper import EndPointWrapper
from satosa_idpyop.endpoint_wrapper import get_http_info

logger = logging.getLogger(__name__)


class CredentialEndpointWrapper(EndPointWrapper):
    wraps = ["credential"]

    def __call__(self, context, *args, **kwargs):
        _http_info = get_http_info(context)
        _entity = self.upstream_get("unit")
        _entity.persistence.restore_state(context.request, _http_info)

        logger.debug(f"request: {context.request}")
        logger.debug(f"https_info: {_http_info}")
        parse_req = self.parse_request(context.request, http_info=_http_info)
        _claims = _entity.persistence.load_claims(parse_req["client_id"])
        logger.debug(f"parse_req: {parse_req}")
        proc_req = self.process_request(context.request, parse_req, _http_info,
                                        extra_claims=_claims)
        if isinstance(proc_req, JsonResponse):
            self.clean_up()  # pragma: no cover
            return proc_req

        logger.debug(f"Process result: {proc_req}")
        if isinstance(proc_req["response_args"], Message):
            response = JsonResponse(proc_req["response_args"].to_dict())
        else:
            response = JsonResponse(proc_req["response_args"])
        self.clean_up()
        return response
