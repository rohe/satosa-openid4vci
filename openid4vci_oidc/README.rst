##################################################
Steps to add the Credential Issuer to a federation
##################################################

Start with copying plugins/orig.openid4vci_frontend.yaml to plugins/openid4vci_frontend.yaml

Some information must be copied from the federation setup to the SATOSA setup.
For this to work you must start by following the steps described in fedservice.setup_federation

Trust anchor
------------

Federation keys for the trust anchor are created when going through the steps in *setup_federation*

The TA's keys can be found in::

    setup_federation/trust_anchor.json

This key set has to be copied into::

    plugins/openid4vci_frontend.yaml

The place where you should copy the key information to looks like this::

    trust_anchors:
        <TRUST_ANCHORS>

To convert the json created by setup.py to yaml needed by SATOSA 
you can use the provided converter::

    ./convert_json_to_yaml.py trust_anchor.json

Replace <TRUST_ANCHORS> with the output from the script above.

Authority hints
---------------

Depends on where in the tree you want to add the credential issuer. The default is to add it
below the trust anchor.

So find the **entity_id** of the trust anchor in *setup_federation/trust_anchor/conf.json*.
Then replace <AUTHORITY_HINTS> with it ::

    authority_hints:
        <AUTHORITY_HINTS>

Remember this is YAML so it would be something like::

    authority_hints:
        - https://example.com

Trust Marks
-----------

Make sure you create a trust mark for the credential issuer over on the setup_federation site
and then replace <TRUST_MARKS> with it::

    trust_marks:
        <TRUST_MARKS>


Adding the credential issuer as a subordinate to the trust anchor
-----------------------------------------------------------------

You have to add information about the credential issuer to the trust anchor.
More specifically you have to add the information to setup_federation/trust_anchor/subordinate.
You should do this by creating a file with something like this inside::

    {
      "https://127.0.0.1:8080": {
        "entity_types": [
          "federation_entity",
          "openid_credential_issuer"
        ],
        "jwks": {
          "keys": [
            {
              "kty": "RSA",
              "use": "sig",
              "kid": "WGZ4OWJWczA0VFFqM29IclY2YzdadDJlcjRpNDFkSkpYblFCWERIVGtsbw",
              "e": "AQAB",
              "n": "ruq63lXrr35nq_J7ZQHBVjmOU97c_79SQMkPi2rJLE0RTszQkzG_UMSWYJrmPynwa9SgDKlizm8hCUJEZRPejbkqRfXS2DOcnXneC-CYZ0smucwSW8Ouab-7Smj6I4zFCFWHhfXINRldGrhtgJ23P6vMQWJ12L33oz_c5nNhfRBklLnqteRvuQ0hZMIo_4LHiWfRj8QLDT8p6MKXVZD2XCkGTgpsGABlKlgorLdcc7Y9X0b0GkOYY7eiE7OhJLqNYa-upbfDx3po9LpTnZVi0efueEyqOD5-fKUKflNJ0I-hcbvpa7pio8e_GBuYvOsHoYRfgZG27UK78AAAa1q2ew"
            },
            {
              "kty": "EC",
              "use": "sig",
              "kid": "M0RpM280WTlUOGVkMnRRcmdjZmVZQ0VVMGxBZmtxbi1HSmc1LVdKZHB0VQ",
              "crv": "P-256",
              "x": "DozqqwXhYS3WWswrS8BS44RT-rbVtFE9fqow1UMg190",
              "y": "JxxjWTtIugaIdcEItO5pFrseDYr59avD7Gdb3n3JN94"
            }
          ]
        }
      }
    }

If you start the credential issuer once it will create its keys and place copies of them in certain files.
The file you have to look for is **public/pid_fed_keys.json**. In it you should have the needed information.
Now copy this file over to the setup_federation site and run (assumed that ci.json is the name of the file)::

    ./add_info.py -s ci.json -t trust_anchor/subordinates

Authentication server
---------------------

Since the credential issuer is a SATOSA frontend it expects there to be a
backend to connect to. The example setup is using a OpenID Connect OP. Namely the
Flask OP example in idpy-oidc. Has to be up and running when you start the SATOSA instance.
This since the backend will do a dynamic client registration to the OP when
it starts.

If you want to use another authentication server you have to replace
idpyoidc_backend.yaml in the **plugins** directory and change the backend reference in
openid4vci_frontend.yaml.