import os

from satosa_openid4vci.core.storage.file import FilesystemDB

_dirname = os.path.dirname(os.path.abspath(__file__))

# add authority_hint

_dir = os.path.join(_dirname, "wp", "authority_hints")

db = FilesystemDB(fdir=_dir,
                  key_conv="idpyoidc.util.Base64",
                  value_conv="idpyoidc.util.JSON")

db.store("authority_hint", value="https://127.0.0.1:7001", key="https://127.0.0.1:7001")

# add trust_anchor

_dir = os.path.join(_dirname, "wp", "trust_anchors")

db = FilesystemDB(fdir=_dir,
                  key_conv="idpyoidc.util.Base64",
                  value_conv="idpyoidc.util.JSON")

val = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "cGdpbkhwVUhaaUFFTW16ckp0alZoaDdGU2pIZWtUU2pCYmpDMW5iWjlvSQ",
            "e": "AQAB",
            "n": "uXRgNfCqC8ypOortnwrfaUZs69KpCVaPrXMb9cSY4E-rMaIh6W1vcXzDZ12BVuiXlksHZ6PcgTBns3s-IS6t1cfIiVrCaEqG3VcFD_FlIooP6PaoF3LJ4KECMhCm23nLUXGOaTx_8CI5pfYcI0talJBYDwTsRF2VaftrH3FzHZWRx_9keU2ZqDyvHmqPpeiG60b8Ncyj_MfaOA40ewQoLX_XOVkv3YrN44JdgSvnTBzka15UAjVoIxuS1ejkhbmZaoEQrzqd9VMXlwvWOmicX6kZRADlZN7kuNOm9mS0cRUUbYPJl0tKQa9_oOCuwnuR5wDHnN-V1_hwx3VgOCMwLQ"
        },
        {
            "kty": "EC",
            "use": "sig",
            "kid": "YzBfYkxrb3lETUlPTnJPdTIyWjRaalJXQVJBVVpTd1U4Q19Ramt3SzdZZw",
            "crv": "P-256",
            "x": "wIDbe83-85kKLDTRNjgfwliwEnC8cgpIccCIGW0wnBY",
            "y": "fkbyzyfjd8vqnXjGDahN5ulBz6SloDuRFZibcJl6q9c"
        }
    ]
}
db.store("authority_hint", value=val, key="https://127.0.0.1:7001")
