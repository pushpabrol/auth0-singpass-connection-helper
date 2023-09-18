# Auth0 - Singpass OIDC Connection Extesion

[![Auth0 Extensions](http://cdn.auth0.com/extensions/assets/badge.svg)]()

This extension will expose endpoints you can use from your OIDC connection to support Singpass token endpoint with client-assertion & JWE

if you already have an OIDC connection setup against Singpass, this extension will modify the Auth0 OIDC connection to allow it to function with Singpass!. This extension updates the token endpoint and the jwks_uri within the OIDC Connection to use endpoints from this extension and exposes the jwks url to be shared with Singpass!


## Usage

Once the webtask has been deployed the OIDC connection you have will be updated to use the  token endpoint and the jwks_uri exposed by this extension

You can use the following url to get the below values

```
https://{TENANT}.{region}.webtask.io/auth0-singpass-connection-extension
```
```
{
  "token": {
    "url": "https://{TENANT}.{region}.webtask.io/auth0-singpass-connection-extension/token",
    "use": "Endpoint used by the Auth0 connection as a token wrapper"
  },
  "jwks": {
    "url": "https://{TENANT}.{region}.webtask.io/auth0-singpass-connection-extension/jwks",
    "use": "Since this wrapper issues its own token for auth0 after verifying with the IDP, this JSON Web Keys(jwks) is used by the connection."
  },
  "keys": {
    "url": "https://{TENANT}.{region}.webtask.io/auth0-singpass-connection-extension/.well-known/keys",
    "use": "JSON Web keys(JWKS) used by the IDP for client assertion validation & JWE. Key with alg: ES256 is used for client assertion validation & Key with alg: ECDH-ES+A128KW is used for token encryption"
  }
}
```

Share the **https://{TENANT}.{region}.webtask.io/auth0-singpass-connection-extension/.well-known/keys** url with the signpass IDP for use for client assertion and encryption


## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free Auth0 Account

1. Go to [Auth0](https://auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## License

This project is licensed under the MIT license.
