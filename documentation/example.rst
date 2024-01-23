.. _example:

*************************************
Introduction to an openid4vci example
*************************************

This example is based on a couple of documents (standards and soon to be standards)

* `OpenID Connect Core 1.0 incorporating errata set 1 <https://openid.net/specs/openid-connect-core-1_0.html>`_
* `OpenID Federation <https://openid.bitbucket.io/connect/openid-federation-1_0.html>`_
* `OpenID for Verifiable Credential Issuance - Editor's draft <https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html>`_
* `Italian EUDI Wallet Technical Specifications <https://github.com/italia/eudi-wallet-it-docs/tree/versione-corrente/docs/en>`_

The software used is:

* `IdpyOIDC <http://github.com/IdentityPython/idpy-oidc>`_ : All things OIDC and OAuth2
* `SATOSA <https://github.com/IdentityPython/satosa>`_ : A configurable proxy for translating between different authentication protocols such as SAML2, OpenID Connect and OAuth2.
* `CryptoJWT <https://github.com/IdentityPython/JWTConnect-Python-CryptoJWT>`_ : Implementation of JW*
* `fedservice <https://github.com/rohe/fedservice>`_ : Implementation of OpenID Federation
* `openid4v <https://github.com/rohe/openid4v>`_ : Implementation of OpenID for Verifiable Credential Issuance

--------------
Example set up
--------------

.. image:: documentation/images/federation_layout.jpeg

The green cloud represents the federation. Note that the wallet is not part of the federation.
The wallet has a relationship to the Wallet Provider and has all the functionality necessary to
read information from the federation.



