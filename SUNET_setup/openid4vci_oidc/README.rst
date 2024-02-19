##################################################
Steps to add the SATOSA frontend to the federation
##################################################

Some information must be copied from the federation setup to the SATOSA setup.

For this to work you must start by running

    cd fed_unit
    tools/setup_fed.py

===========================================
From federation_entities to openid4vci_oidc
===========================================

Trust marks
-----------

Remaining in the **fed_unit** directory you have to create a trust mark for the
credential issuer. The script to use for this is *fed_unit/create_trust_mark.py*
In it's general form the command is::

    create_trust_mark.py <trust_mark_issuer_ref> <subject_entity_id> <trust_mark_id>

As and example this in the basic setup would be::

    create_trust_mark.py tmi https://127.0.0.1:8080 http://dc4eu.example.com/PersonIdentificationData/se

For the following to work it is assumed that you are in the **openid4vci_oidc**
directory.

Trust marks


#### PID Issuer

One of the effects of running setup.py is the creating of four sets of
keys. A federation key set and four application protocol key sets.
The federation key set is found in:

    private/pid_fed_keys.json

The protocol key sets are in: 

    private/pid_oci_keys.json
    private/pid_crypt_keys.json
    private/pid_token_handler_keys.json
    private/pid_session_keys.json

These five key sets has to be copied over to the SATOSA setup:

    cp private/pid_*.json ../openid4vci_oidc/private

#### Trust anchor

Federation keys for the trust anchor is also created by running setup.py .
The TA's keys can be found in:

    private/fed_dc4eu_keys.json

This key set has to be copied into:

    openid4vci_oidc/plugins/openid4vci_frontend.yaml

The place where you should copy the key information to looks like this:

    trust_anchors:
        https://127.0.0.1:7001:
          keys: null

To convert the json created by setup.py to yaml needed by SATOSA 
you can use the provided converter:

    ./convert_json_to_yaml.py static/dc4eu_fed_keys.json

Replace "keys: null" with the output from the script above.
The output should look something like this:

    keys:
        - e: AQAB
          kid: cGdpbkhwVUhaaUFFTW16ckp0alZoaDdGU2pIZWtUU2pCYmpDMW5iWjlvSQ
          kty: RSA
          n: uXRgNfCqC8ypOortnwrfaUZs69KpCVaPrXMb9cSY4E-rMaIh6W1vcXzDZ12BVuiXlksHZ6PcgTBns3s-IS6t1cfIiVrCaEqG3VcFD_FlIooP6PaoF3LJ4KECMhCm23nLUXGOaTx_8CI5pfYcI0talJBYDwTsRF2VaftrH3FzHZWRx_9keU2ZqDyvHmqPpeiG60b8Ncyj_MfaOA40ewQoLX_XOVkv3YrN44JdgSvnTBzka15UAjVoIxuS1ejkhbmZaoEQrzqd9VMXlwvWOmicX6kZRADlZN7kuNOm9mS0cRUUbYPJl0tKQa9_oOCuwnuR5wDHnN-V1_hwx3VgOCMwLQ
          use: sig
        - crv: P-256
          kid: YzBfYkxrb3lETUlPTnJPdTIyWjRaalJXQVJBVVpTd1U4Q19Ramt3SzdZZw
          kty: EC
          use: sig
          x: wIDbe83-85kKLDTRNjgfwliwEnC8cgpIccCIGW0wnBY
          y: fkbyzyfjd8vqnXjGDahN5ulBz6SloDuRFZibcJl6q9c

### Authority hints

The content of 

    cred/pid_authority_hints.json 

must be copied into:

    openid4vci_oidc/plugins/openid4vci_frontend.yaml

look for

    authority_hints

and add the urls from "pid_authority_hints.json" to "openid4vci_frontend.yaml".
Taking care to convert from JSON to YAML as necessary.

### Trust Marks

The content of 

    cred/pid_trust_marks.json 

must be copied into:

    openid4vci_oidc/plugins/openid4vci_frontend.yaml

look for

    trust_marks:

and add the base64 encoded trust marks from "pid_trust_marks.json" to "openid4vci_frontend.yaml".
Taking care to convert from JSON to YAML as necessary.

