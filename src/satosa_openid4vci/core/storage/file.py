from typing import Optional

from idpyoidc.storage.abfile import AbstractFileSystem

from .base import Storage

DIVIDER = ":::"

class FilesystemDB(AbstractFileSystem, Storage):

    def __init__(
            self,
            fdir: Optional[str] = "",
            key_conv: Optional[dict] = None,
            value_conv: Optional[dict] = None,
            **kwargs
    ):
        AbstractFileSystem.__init__(self, fdir, key_conv, value_conv)

    def fetch(self, information_type: str, key: Optional[str] = ""):
        if key:
            return self.get(DIVIDER.join([information_type, key]))
        else:
            return self.get(information_type)

    def store(self, information_type: str, value, key: Optional[str] = ""):
        if key:
            self[DIVIDER.join([information_type, key])] = value
        else:
            self[information_type] = value

    def keys_by_information_type(self, information_type: str):
        itype = f"{information_type}:"
        return [k.split(DIVIDER)[1] for k in self.keys() if k.startswith(itype)]

    def information_types(self):
        return {k.split(DIVIDER)[0] for k in self.keys()}
