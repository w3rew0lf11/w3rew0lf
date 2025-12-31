# OAuth 2.0

**OAuth is a permission system.**

It lets one app access *limited* data from another app **without giving your password**

- **User** wants App A to do something with App B.
- App B doesn't want the user to give their **password** to App A.
- So App B gives App A a **token**.
- That token gives **limited access** (only what the user allowed).

https://oauth.net/2/

## **OAuth 2.0 Framework**

****Access Tokens: An OAuth Access Token is a string that the OAuth client uses to make requests to the resource server.

Refresh Tokens: An OAuth Refresh Token is a string that the OAuth client can use to get a new access token without the user's interaction.

OAuth Scope: Scope is a mechanism in OAuth 2.0 to limit an application's access to a user's account. An application can request one or more scopes, this information is then presented to the user in the consent screen, and the access token issued to the application will be limited to the scopes granted.

## Basic OAuth flow

3 major parties involved:

Client app: The web app requesting access

Resource Server:  server at client application who wants to access the client data

Authorization server: server that control user’s  data and have access to it

example:

app have login with google option

when we click on it the app sends a get request to authorization server:

```python
GET /authorize?
	respose_type=code&
	client_id=client123&
	redirect_uri=https://client.com/callback&
	scope=openid profile email&
	state=xyz123
Host: authserver.com
```

now user is prompted to login and after logging in there comes an authorization response which the Oauth provider sends back to the app and the response looks something like this

```python
HTTP/1.1 302 Found
Location: https://client.com/callback?code=abc123&state=xyz123
```

and the provider redirect the user to the url that contain a callback with a value of code and now we have the code value we need to exchange it for the access token 

now the client app sends a post request to exchange the code value for access token and the request looks something like this

```json
POST /blog-images/Oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=abc123xyz
&redirect_uri=https://yourapp.com/callback
&client_id=your_client_id
&client_secret=your_client_secret
```

now comes the token response which the oauth provider sends back to client contains the access token, type and expiration of the token and refresh token value like below:

```json
{
"access_token":"eyJhv........",
"token_type":"Bearer",
"expires_in":360,
"refresh_token":"adva434v",
"scope":"read write"
}
```

now the client app can access user data by putting the access token in the http request 

## Oauth 2.0 flows or grant types:

Implicit flow

Authorization code flow

PKCE

OpenID Connect

Device Code

## Implicit flow:

OAuth Implicit Flow is one of the four authentication and authorization flows used across different platforms and applications. This flow is designed for mobile applications or single-page applications (SPAs), wherein the client-side JavaScript code directly communicates with the authorization server of the OAuth provider.

The Implicit Flow allows access tokens to be obtained without exchanging client secrets. After the user has granted authorization, the authorization server directly returns the access token to the client application. The access token is then sent directly to the client-side JavaScript code without the need for a temporary code exchange for the access token.

The implicit flow is depreciated and is not used anymore but still we need to understand it.

![image.png](blog-images/Oauth/image.png)

 **1. Build the Authorization URL**

Before authorization begins, it first generates a random string to use for the `state` parameter. The client will need to store this to be used in the next step.

```bash
https://authorization-server.com/authorize?
  response_type=token
  &client_id=RwsJe27-RqYKu6SR1AYxxaof
  &redirect_uri=https://www.oauth.com/playground/implicit.html
  &scope=photo
  &state=Qt25US60bA51bj8O
```

For this demo, we've gone ahead and generated a random state parameter (shown above) and saved it in a cookie.

now we will be taken to the authorization server where we need to enter the username and password.

now after we enter credentialns and login:

**An application would like to connect to our account**

The application "OAuth 2.0 Playground" would like the ability to access our photos.

we approve of it

 **2. Verify the state parameter**

The user was redirected back to the client, and you'll notice there is now a fragment component in the URL that contains the access token as well as some other information:

```
#access_token=R3a3KJ8jYkCz_V-HgnyliVPMMcfeHubuWxghmQvW3mKm0faTJYRhkL0BdSs39_CYp3vKywNv&token_type=Bearer&expires_in=86400&scope=photos&state=Qt25US60bA51bj8O
```

You need to first verify that the `state` parameter matches the value stored in this user's session so that you protect against CSRF attacks.

> This does not stop a malicious actor from injecting an access token into your client. There is no solution in OAuth for protecting the Implicit flow, and it is [being deprecated in the Security BCP](https://oauth.net/2/grant-types/implicit/).
> 

Depending on how you've stored the `state` parameter (in a cookie, session, or some other way), verify that it matches the state that you originally included in step 1. Previously, we had stored the state in a cookie for this demo.

Does the state stored by the client (`Qt25US60bA51bj8O`) match the state in the redirect (`Qt25US60bA51bj8O`)?

**if it matches**

 **3. Extract the access token**

That's it! Now that you've verified the state parameter, you can start using the access token that was provided in the URL fragment.

For reference, here are the values the client is ready to use.

| access_token | `R3a3KJ8jYkCz_V-HgnyliVPMMcfeHubuWxghmQvW3mKm0faTJYRhkL0BdSs39_CYp3vKywNv` |
| --- | --- |
| token_type | `Bearer` |
| expires_in | `86400` |
| scope | `photos` |

Note that this is an OAuth 2.0 Bearer Token, which means it is opaque to the client and the client should not try to parse the token. Some authorization servers may use JWT values, but others may use random strings. This is in contrast to an OpenID Connect ID Token which is intended to be parsed by the client. See the [OpenID Connect](https://www.oauth.com/playground/oidc.html) for an example of parsing an ID token.

> **it sends token with user creds so we can change the email to some one else to get logged in without password and also can test for the open redirect**
> 

---

## Authorization code flow

![image.png](blog-images/Oauth/image%201.png)

The Authorization Code Flow in Auth0 is a secure OAuth 2.0 authorization flow designed for confidential applications, such as regular web applications, where client credentials can be kept secure. This flow involves exchanging an authorization code for access and ID tokens after user authentication and consent.
The process begins when a user selects a login option within the application, prompting the application to redirect the user to Auth0’s authorization endpoint (/authorize). At this stage, the user authenticates using configured login methods and may be presented with a consent prompt detailing the permissions being requested.

 **1. Build the Authorization URL**

Before authorization begins, it first generates a random string to use for the `state` parameter. The client will need to store this to be used in the next step.

```
https://authorization-server.com/authorize?
  response_type=code
  &client_id=RwsJe27-RqYKu6SR1AYxxaof
  &redirect_uri=https://www.oauth.com/playground/authorization-code.html
  &scope=photo+offline_access
  &state=YJeRzotznVPRN7ub
```

For this demo, we've gone ahead and generated a random state parameter (shown above) and saved it in a cookie.

now we will be taken to the authorization server where we need to enter the username and password.

now after we enter credentialns and login:

**An application would like to connect to our account**

The application "OAuth 2.0 Playground" would like the ability to access our photos.

 **2. Verify the state parameter**

The user was redirected back to the client, and you'll notice a few additional query parameters in the URL:

```
?state=YJeRzotznVPRN7ub&code=vVY_qsLFu2HltZDUlAeMR-sIRiblQqos2IKtL5z6qiir1tkE
```

You need to first verify that the `state` parameter matches the value stored in this user's session so that you protect against CSRF attacks.

Depending on how you've stored the `state` parameter (in a cookie, session, or some other way), verify that it matches the state that you originally included in step 1. Previously, we had stored the state in a cookie for this demo.

Does the state stored by the client (`YJeRzotznVPRN7ub`) match the state in the redirect (`YJeRzotznVPRN7ub`)?

**if it matches**

 **3. Exchange the Authorization Code**

Now you're ready to exchange the authorization code for an access token.

The client builds a POST request to the token endpoint with the following parameters:

```
POST https://authorization-server.com/token

grant_type=authorization_code
&client_id=RwsJe27-RqYKu6SR1AYxxaof
&client_secret=SQNv_oibDr8U5GUe1nhFlkvEGb5hkmS8wafDRhNWlQ7kwXGs
&redirect_uri=https://www.oauth.com/playground/authorization-code.html
&code=vVY_qsLFu2HltZDUlAeMR-sIRiblQqos2IKtL5z6qiir1tkE

```

> Note that the client's credentials are included in the POST body in this example. Other authorization servers may require that the credentials are sent as a HTTP Basic Authentication header.
> 

 **Token Endpoint Response**

Here's the response from the token endpoint! The response includes the access token and refresh token.

```
{
  "token_type": "Bearer",
  "expires_in": 86400,
  "access_token": "3RMj_HemjPZq_-o_3Kg4_OxXL2ewzFPlsdSaGwcEKUfgQ7TjYecX4vgLHjguGz3rl7ZHd7MC",
  "scope": "photo offline_access",
  "refresh_token": "oj1BbOtf6mcLj1bs1Gz2DXwi"
}
```

Great! Now your application has an access token, and can use it to make API requests on behalf of the user.

> **we can test for open redirect and code reuse or replay attack**
> 

---

## PKCE

**Proof Key for Code Exchange**

![image.png](blog-images/Oauth/image%202.png)

The Authorization Code with PKCE (Proof Key for Code Exchange) flow is a secure method for public clients, such as single-page applications (SPAs) and mobile apps, to obtain access tokens without needing to store a client secret securely.
This flow strengthens the OAuth 2.0 authorization process by preventing attacks like code interception, which are possible in less secure flows

The process begins with the client generating a cryptographically random string called a code verifier, which must be between 43 and 128 characters long.
This code verifier is then transformed into a code challenge using a hashing algorithm, typically SHA-256, and encoded in Base64 URL format.
The code challenge is sent to the authorization server during the initial authorization request, along with the code_challenge_method parameter, usually set to S256.

 **1. Create a Code Verifier and Challenge**

Before redirecting the user to the authorization server, the client first generates a secret code verifier and challenge.

The code verifier is a cryptographically random string using the characters A-Z, a-z, 0-9, and the punctuation characters -._~ (hyphen, period, underscore, and tilde), between 43 and 128 characters long.

Once the client has generated the code verifier, it uses that to create the code challenge. For devices that can perform a SHA256 hash, the code challenge is a BASE64-URL-encoded string of the SHA256 hash of the code verifier. Otherwise, the same verifier string is used as the challenge.

generate code verifier

```
bmz9mZVfuf1QhKcIZ4kqkAYEITOuaAneXEvpEtHsS96xLle0

```

generate code challange

`base64url(sha256(code_verifier))`

```
uUCuCmJq_mUpa2YbOiSFZc6u89jd2GBN2gm8rdFNyHk
```

The client needs to store the `code_verifier` for later use. We will store it in a cookie for this demo.

after this

 **2. Build the Authorization URL**

The client then needs to generate a random string to use for the `state` parameter, and needs to store it to be used in the next step.

```
https://authorization-server.com/authorize?
  response_type=code
  &client_id=RwsJe27-RqYKu6SR1AYxxaof
  &redirect_uri=https://www.oauth.com/playground/authorization-code-with-pkce.html
  &scope=photo+offline_access
  &state=7PSti4bOgf-mCY4_
  &code_challenge=uUCuCmJq_mUpa2YbOiSFZc6u89jd2GBN2gm8rdFNyHk
  &code_challenge_method=S256
```

For this demo, we've gone ahead and generated a random state parameter and saved it in a cookie along with the `code_verifier` previously generated.

The client includes the `code_challenge` parameter in this request, which the authorization server will store and compare later during the code exchange step.

now we will be taken to the authorization server where we need to enter the username and password.

now after we enter credentialns and login:

**An application would like to connect to our account**

The application "OAuth 2.0 Playground" would like the ability to access our photos.

 **3. Verify the state parameter**

The user was redirected back to the client with a few additional query parameters in the URL:

```
?state=7PSti4bOgf-mCY4_&code=P_RPHFsJQQ6yZwmMXOeoNOJ3uC1nZvXcV--SBjYoulccoqC9
```

The state value isn't strictly necessary here since the PKCE parameters provide CSRF protection themselves. In practice, if you're sure the OAuth server supports PKCE, you can use the state parameter for application state instead of using it for CSRF protection.

Does the state stored by the client (`7PSti4bOgf-mCY4_`) match the state in the redirect (`7PSti4bOgf-mCY4_`)?

**if it matches**

 **4. Exchange the Authorization Code**

Now you're ready to exchange the authorization code for an access token.

The client will build a POST request to the token endpoint with the following parameters:

```
POST https://authorization-server.com/token

grant_type=authorization_code
&client_id=RwsJe27-RqYKu6SR1AYxxaof
&client_secret=SQNv_oibDr8U5GUe1nhFlkvEGb5hkmS8wafDRhNWlQ7kwXGs
&redirect_uri=https://www.oauth.com/playground/authorization-code-with-pkce.html
&code=P_RPHFsJQQ6yZwmMXOeoNOJ3uC1nZvXcV--SBjYoulccoqC9
&code_verifier=bmz9mZVfuf1QhKcIZ4kqkAYEITOuaAneXEvpEtHsS96xLle0

```

Remember the `code_verifier`? You'll need to send that along with the token request. The authorization server will check whether the verifier matches the challenge that was used in the authorization request. This ensures that a malicious party that intercepted the authorization code will not be able to use it.

 **Token Endpoint Response**

Here's the response from the token endpoint! The response includes the access token and refresh token.

```
{
  "token_type": "Bearer",
  "expires_in": 86400,
  "access_token": "7KbxcGqmop3lRtfI5Zyfa0VSumUJhU5b0nHNMpwbyVX_-iymXORd-es4SMy0IXvofig0ePM8",
  "scope": "photo offline_access",
  "refresh_token": "AeBqE8xDtmF4jLOixolY3PaI"
}
```

Great! Now your application has an access token, and can use it to make API requests on behalf of the user.

> **Test for:
open redirect
authorization code reuse vulnerability
code verifier reuse**
> 

---

# OpenID Connect

The OpenID Connect (OIDC) Authorization Code Flow is a widely used authentication protocol that enables clients to verify the identity of end users based on the authentication performed by an authorization server or **identity provider (IdP)**, while also obtaining basic profile information in a secure and interoperable manner.
This flow is built on top of the OAuth 2.0 framework and is designed for clients that can securely store client secrets, such as web applications with server-side logic.

> **Open Id connect does both authentication and authorization**
> 

![image.png](blog-images/Oauth/image%203.png)

The flow begins when the client (Relying Party, or RP) constructs an authorization request and redirects the end user to the OpenID Provider (OP) authorization endpoint.
The request includes essential parameters such as client_id, response_type=code, scope=openid (which is mandatory for OpenID Connect), redirect_uri, and a state parameter to prevent cross-site request forgery (CSRF) attacks.
The nonce parameter is also recommended to mitigate replay attacks by associating the client session with the ID token.
Additional parameters like code_challenge and code_challenge_method may be included if the Proof Key for Code Exchange (PKCE) extension is used for enhanced security.

 **1. Build the Authorization URL**

OpenID Connect supports many of the same flows as OAuth 2.0. At the end of the OpenID Connect process, the client ends up with an "ID Token", which contains information about the user who signed in. This token is encoded and signed, and the client is expected to parse it directly. When a client uses an OpenID Connect flow, it can request an access token in addition to an ID token.

In this example, we'll cover the OpenID Connect Authorization Code flow and request an ID token as well as an access token.

Before authorization begins, it first generates a random string to use for the `state` parameter. The client will need to store this to be used in the next step.

```
https://authorization-server.com/authorize?
  response_type=code
  &client_id=Fd5Pq0S0DXWC2qVWfCRPYBa_
  &redirect_uri=https://www.oauth.com/playground/oidc.html
  &scope=openid+profile+email+photos
  &state=adnBxr2mYn4IiNKc
  &nonce=RoR1dfckUaA6UHIC
```

For this demo, we've gone ahead and generated random state and nonce parameters (shown above) and saved them in a cookie.

now we will be taken to the authorization server where we need to enter the username and password.

 after that we enter credentialns and login:

**An application would like to connect to our account**

The application "OAuth 2.0 Playground" would like the ability to access our photos.

 **2. Verify the state parameter**

The user was redirected back to the client, and you'll notice a few additional query parameters in the URL:

```
?state=adnBxr2mYn4IiNKc&code=SgIQ51Ah3RmT5uGsPxanja__2IufhZqY3Uup4gIhlRKCW_tl
```

You need to first verify that the `state` parameter matches the value stored in this user's session so that you protect against CSRF attacks.

Depending on how you've stored the `state` parameter (in a cookie, session, or some other way), verify that it matches the state that you originally included in step 1. Previously, we had stored the state in a cookie for this demo.

Does the state stored by the client (`adnBxr2mYn4IiNKc`) match the state in the redirect (`adnBxr2mYn4IiNKc`)?

**If it matches**

 **3. Exchange the Authorization Code**

Now you're ready to exchange the authorization code for an access token.

The client builds a POST request to the token endpoint with the following parameters:

```
POST https://authorization-server.com/token

grant_type=authorization_code
&client_id=Fd5Pq0S0DXWC2qVWfCRPYBa_
&client_secret=h_RBqEJqBjpVf1zFfb7rk6RKdT6WL7vdfl5GHSlOyJGrAu0J
&redirect_uri=https://www.oauth.com/playground/oidc.html
&code=SgIQ51Ah3RmT5uGsPxanja__2IufhZqY3Uup4gIhlRKCW_tl

```

Note that the client's credentials are included in the POST body in this example. Other authorization servers may require that the credentials are sent as a HTTP Basic Authentication header.

 **Token Endpoint Response**

Here's the response from the token endpoint! The response includes the ID token and access token.

```
{
  "token_type": "Bearer",
  "expires_in": 86400,
  "access_token": "jiq-uvzQOSFIrsfrGeI9tQcO3f1HgzC4m4EQcskdlSIkmxGkZH4qhf8olutoE7qqzg2K5pk9",
  "scope": "openid profile email photo",
  "id_token": "eyJraWQiOiJzMTZ0cVNtODhwREo4VGZCXzdrSEtQUkFQRjg1d1VEVGxteW85SUxUZTdzIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ1bnVzdWFsLWxlb3BhcmRAZXhhbXBsZS5jb20iLCJuYW1lIjoiVW51c3VhbCBMZW9wYXJkIiwiZW1haWwiOiJ1bnVzdWFsLWxlb3BhcmRAZXhhbXBsZS5jb20iLCJpc3MiOiJodHRwczovL3BrLWRlbW8ub2t0YS5jb20vb2F1dGgyL2RlZmF1bHQiLCJhdWQiOiJGZDVQcTBTMERYV0MycVZXZkNSUFlCYV8iLCJpYXQiOjE3NjcxNDcxMzUsImV4cCI6MTc2OTczOTEzNSwiYW1yIjpbInB3ZCJdfQ.ZoPvZPaomdOnnz2GFRGbgaW7PPWIMFDqSBp0gbN4An4a9F-Bc-4_T9EBGV8aGetyjZYAON0gjNV0p0NGFiwettePWKuxBzusuGCEd9iXWWUO9-WTF5e2AGr3_jkg34dbxfiFXy3KgH7m0czm809cMaiZ_ofLYgJHVD8lqMQoWifhoNhpjPqa19Svc3nCHzSYHUgTXQWvA56NmQvyVPh_OM7GMpc6zHopmihJqt3eREof8N-bOd7FL39jeam2-k1TFSDogyJE513aC0OssRADr_TWvtL8xoaPkXM_7bXYs9_7erXmzF9la0hvmOuasieetpLhOvFeoiOJWCU9xhxj4Q"
}
```

Your application can use the access token to make API requests on behalf of the user.

> **We can try different types of JWT attacks here and we should also try open redirect**
> 

---

# Device Code

The OAuth 2.0 Device Code Flow, defined in RFC 8628, is designed for devices with limited input capabilities, such as smart TVs, media consoles, or IoT devices, enabling them to obtain authorization through a secondary device like a smartphone or computer.
The flow begins when the device client sends an HTTP POST request to the authorization server's device authorization endpoint, including its client identifier and optionally the requested scope.
In response, the authorization server issues a device code, a user code, a verification URI, and specifies an expiration time and polling interval.

![image.png](blog-images/Oauth/image%204.png)

 **1. Request a Device Code**

The first step of the Device flow is to request a device code. This is done with a simple POST request to the device code endpoint.

```
POST https://example.okta.com/device

client_id=https://www.oauth.com/playground/
```

**we send post request**

 **2. Tell the User to Enter the Code**

The response from the server includes the device code, a code to display to the user, and the URL the user should visit to enter the code.

```
{
  "device_code": "NGU5OWFiNjQ5YmQwNGY3YTdmZTEyNzQ3YzQ1YSA",
  "user_code": "BDWD-HQPK",
  "verification_uri": "https://example.okta.com/device",
  "interval": 5,
  "expires_in": 1800
}
```

*Note: This is just an example URL, since the Okta API does not implement the Device Flow. You can use the [Google API](https://developers.google.com/identity/protocols/OAuth2ForDevices) if you want to try this against a real service.*

You'll need to present the `verification_uri` and `user_code` to the user and instruct them to enter the code at the URL. How you do this depends on the capabilities of the device. For example, on a smart TV, it is relatively easy to display both items and instructional text on the screen. On a device with a more limited display capability, it may be more challenging.

 **3. Poll the Token Endpoint**

While you wait for the user to visit the URL, sign in to their account, and approve the request, you'll need to poll the token endpoint with the device code until an access token or error is returned.

```
POST https://example.okta.com/token

grant_type=urn:ietf:params:oauth:grant-type:device_code
&client_id=https://www.oauth.com/playground/
&device_code=NGU5OWFiNjQ5YmQwNGY3YTdmZTEyNzQ3YzQ1YSA
```

**we poll the token endpoint**

Before the user has finished signing in and approving the request, the authorization server will return a status indicating the authorization is still pending.

```
HTTP/1.1 400 Bad Request

{
  "error": "authorization_pending"
}
```

**we poll again until we succeed** 

When the user approves the request, the token endpoint will respond with the access token.

```
HTTP/1.1 200 OK

{
  "token_type": "Bearer",
  "access_token": "RsT5OjbzRn430zqMLgV3Ia",
  "expires_in": 3600,
  "refresh_token": "b7a3fac6b10e13bb3a276c2aab35e97298a060e0ede5b43ed1f720a8"
}
```

Now the device can use this access token to make API requests on behalf of the user.

> **device code shoud have some intervals between polling otherwise we can brute-force the device code**
> 

Reference:

https://www.oauth.com/playground/index.html

https://payatu.com/blog/how-oauth-implicit-flow-led-to-hundreds-of-user-accounts-being-accessed/