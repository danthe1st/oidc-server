# OIDC-server

This project contains an _OpenID Provider_ which can be used to provide central authentication for different services. For example, the "Login with Google/GitHub/etc" functionality you might see some websites using are based on OpenID Connect (OIDC). This project implements exactly that functionality and acts as a service that can be used to authenticate against.

### How does it work

Any service (_Relying Party_) wanting to authenticate users with an OIDC provider needs to have a client ID and client secret that can be used for that purpose. These credentials are used to ensure the user knows who is attempting to authenticate them and who will get information about their data when the authentication completes.

This project contains some endpoints allowing to create "apps" with a client ID and client secret.

Once an app is created, any service in posession of these credentials can use them to authenticate users. To do that, it has to perform the following steps:
- The user is redirected to `/oidc/authorize` with some information about the client trying to authenticate them and the redirect URI which is later used to return to the service wanting to authenticate the user.
- The user has to log in if they haven't already.
- The user is asked whether they want to authenticate to the service.
- If they accept, a `POST` request is sent to `/oidc/authorize` and the server redirects the user to the redirect URI with an aditional authorization code.
- The application wanting to authenticate the user sends a request to `/oidc/token` which includes the token from `/oidc/authorize` as well as its own client ID and client secret. This ensures that only the actual application can use that information from the user. The server (OpenID provider) responds with an _access token_ and an _id token_. The ID token contains basic information about the user proving they are authenticated and is signed by the server. The _access token_ can be used by the application to retrieve some information about the user.
- The application sends a request to `/oidc/userinfo` containing the access token to get information about the user. Once that request succeeds, the application can consider the user to be authenticated.

### Sample client

The [`simple-oidc-client`](./simple-oidc-client) project contains a simple server that can be used to authenticate against the OIDC server provided the client ID and client secret are properly set up. That project doesn't contain any OIDC-specific code, it just uses Spring Security's support for OIDC.