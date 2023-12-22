import logging
from typing import Optional

from idpyoidc.storage.abfile import AbstractFileSystem

from .base import Storage

logger = logging.getLogger(__name__)

DIVIDER = ":::"

class FilesystemDB(AbstractFileSystem, Storage):

    def __init__(
            self,
            fdir: Optional[str] = "",
            key_conv: Optional[str] = None,
            value_conv: Optional[str] = None,
            **kwargs
    ):
        AbstractFileSystem.__init__(self, fdir, key_conv, value_conv)

    def fetch(self, information_type: str, key: Optional[str] = ""):
        logger.debug(f"Fetching {information_type}{DIVIDER}{key} from persistent storage")
        if key:
            return self.get(DIVIDER.join([information_type, key]))
        else:
            return self.get(information_type)

    def store(self, information_type: str, value, key: Optional[str] = ""):
        logger.debug(f"Storing {information_type}{DIVIDER}{key} to persistent storage")
        if key:
            self[DIVIDER.join([information_type, key])] = value
        else:
            self[information_type] = value

    def keys_by_information_type(self, information_type: str):
        itype = f"{information_type}:"
        return [k.split(DIVIDER)[1] for k in self.keys() if k.startswith(itype)]

    def information_types(self):
        return {k.split(DIVIDER)[0] for k in self.keys()}
