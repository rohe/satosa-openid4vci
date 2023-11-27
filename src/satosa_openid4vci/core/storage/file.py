from typing import Optional

from idpyoidc.storage.abfile import AbstractFileSystem

from .base import Storage


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
            return self.get(":".join([information_type, key]))
        else:
            return self.get(information_type)

    def store(self, information_type: str, value, key: Optional[str] = ""):
        if key:
            self[":".join([information_type, key])] = value
        else:
            self[information_type] = value

    def keys_by_information_type(self, information_type: str):
        itype = f"{information_type}:"
        return [k.split(':')[1] for k in self.keys() if k.startswith(itype)]

    def information_types(self):
        return {k.split(":")[0] for k in self.keys()}
