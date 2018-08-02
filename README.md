# HMAC+HKDF Authentication Library

A library to facility HMAC+HKDF style authentication.

## HMAC+HKDF Authentication

HMAC+HKDF Authentication is an Authentication method that allows ensures the request is not tampered with in transit. This provides resiliance not only against network layer manipulation, but also man-in-the-middle attacks.

At a high level, an HMAC signature is created based upon the raw request body, the HTTP method, the URI (with query parameters, if present), and the current date. In addition to ensuring the request cannot be manipulated in transit, it also ensures that the reqest is timeboxed, effectively preventing replay attacks.

The library itself is made available by importing the following struct:

Supporting API's will return the following payload containing at minimum the following information.

```json
{
    "access_token": "7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA",
    "refresh_token": "MA2JX5FXWS57DHW4OIHHQDCJVGS3ZKKFCL7XM4GNOB567I6ER4LQ",
    "ikm": "bDEyECRvKKE8w81fX4hz/52cvHsFPMGeJ+a9fGaVvWM=",
    "signing": "ecYXfAwNVoS9ePn4xWhiJOdXQzr6LpJIeIn4AVju/Ug=",
    "hash": "822d1a496b11ce6639fec7a2993ba5c02153150e45e5cec5132f3f16bfe95149",
    "expires_at": 1472678411
}
```

After extracting the elements, we can create signed request by doing the following:

```swift
let token = try KDFAuth.createToken(accessToken, refreshToken, ikm, signing, expiresAt)
let authentication = KDFAuth.getAuthorizationData(httpMethod, uri, token, date, requestBody)
```

A trivial full example is shown as follows:

```swift
let request: Data? = "{ \"foo\": \"bar\" }".data(using: .utf8)
let authentication = KDFAuth.getAuthorizationData("GET", "/api/v1/user/index", token, Date(), request)
```

> Note that the `date` parameter should be pre-offset when calling `getAuthorizationData` to prevent time skewing.

### Version 1 HMAC Header

For API's using version 1 of the HMAC header, your header would be constructed as follows:

```swift
let header = "HMAC " + token.accessToken + "," + authroization.getEncodedHMAC() + "," + authorization.getEncodedSalt()
```

This string can be used in the `Authorization` Header

### Version 2 HMAC Header

The Version 2 HMAC header, for API's that support it can be retrieved by calling:

```swift
let header = "HMAC " + authorization.getV2Header(token)
```

### Date Header

The `X-Date` header can be retrieved by calling `authorization.getDateString()`

## Encrypted Requests & Responses

This library enables clients coding in Swift 4 to establish and trusted encrypted session on top of a TLS layer, while simultaniously (and independently) providing the ability authenticate and identify a client via HMAC+HKDF style authentication.

The rationale for this functionality includes but is not limited to:

1. Necessity for extra layer of security
2. Lack of trust in the network or TLS itself (see https://blog.cloudflare.com/incident-report-on-memory-leak-caused-by-cloudflare-parser-bug/)
3. Need to ensure confidentiality of the Initial Key Material (IKM) provided by the server for HMAC+HKDF authentication
4. Need to ensure confidentiality of user submitted credentials to the API for authentication

The primary reason you may want to establish an encrypted session with the API itself is to ensure confidentiality of the IKM to prevent data leakages over untrusted networks to avoid information being exposed in a Cloudflare like incident (or any man-in-the-middle attack). Encrypted sessions enable you to utilize a service like Cloudflare should a memory leak occur again with confidence that the IKM and other secure data would not be exposed.

### Encrypted Request Body

Payloads can be encrypted as follows:

```swift
let session = KDFAuth.createSession(key)
let request: Data? = "{ \"foo\": \"bar\" }".data(using: .utf8)
let encryptedBody = session.encryptRequest(rawRequest)
```

> Note that you need to have a pre-bootstrapped security key to encrypt data. Typically this is returned by `/api/v1/server/otk`

### Decrypting Responses

Encrypted responses can be decrypted as follows:

```swift
let response = Data(base64Encoded: "b64response...=")!

// Signature checking is optional, but is recommended to verify the authenticity of the response
let encryptedResponse = KDFAuth.createEncryptedResponse(publicKeyHeader, nonce, hashIdHeader, response, signatureHeader, signaturePublicKeyHeader)

let decryptedResponse = try session.decryptResponse(encryptedResponse)
```

The decrypted response will be returned as a `String`, and can be manipulated back to whatever format you prefer.