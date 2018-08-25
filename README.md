# ncryptf Swift

<center>
    <img src="https://github.com/charlesportwoodii/ncryptf-swift/blob/master/logo.png?raw=true" alt="ncryptf logo" width="400px"/>
</center>

A library for facilitating hashed based KDF signature authentication, and end-to-end encrypted communication with compatible API's.

| OS    | Build Status |
|-------|------|
| Linux | ![](https://travis-ci-job-status.herokuapp.com/badge/charlesportwoodii/ncryptf-swift/master/linux?style=flat-square)](https://travis-ci.org/charlesportwoodii/ncryptf-swift |
| MacOS | ![](https://travis-ci-job-status.herokuapp.com/badge/charlesportwoodii/ncryptf-swift/master/osx?style=flat-square)](https://travis-ci.org/charlesportwoodii/ncryptf-swift) |

## Installing

This library can be installed via Swift Package Manager by adding the following dependency

```swift
dependencies: [
    .package(url: "https://github.com/charlesportwoodii/ncryptf-swift.git", .branch("master"))
],
```

## Testing

### MacOS

MacOS tests run via the swift test command
```
swift test
```

### Linux

Linux tests can be run either locally, or through the provided docker container

#### Local Testing
```
apt install libsodium-dev
swift test
```

#### Docker Testing

If you're working on a platform that doesn't support swift or XCTestCase, you run the test suite through Docker

First, build the docker image
```
docker build --tag ncryptf --compress --squash .
```

Then the tests can be run as follows:
```
docker run -it -v${PWD-.}:/package ncryptf swift test
```

## HMAC+HKDF Authentication

HMAC+HKDF Authentication is an Authentication method that allows ensures the request is not tampered with in transit. This provides resiliance not only against network layer manipulation, but also man-in-the-middle attacks.

At a high level, an HMAC signature is created based upon the raw request body, the HTTP method, the URI (with query parameters, if present), and the current date. In addition to ensuring the request cannot be manipulated in transit, it also ensures that the reqest is timeboxed, effectively preventing replay attacks.

The library itself is made available by importing the following struct:

Supporting API's will return the following payload containing at minimum the following information.

```json
{
    "access_token": "7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA",
    "refresh_token": "7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA",
    "ikm": "bDEyECRvKKE8w81fX4hz/52cvHsFPMGeJ+a9fGaVvWM=",
    "signing": "ecYXfAwNVoS9ePn4xWhiJOdXQzr6LpJIeIn4AVju/Ug=",
    "expires_at": 1472678411
}
```

After extracting the elements, we can create signed request by doing the following:

```swift
let auth = try? Authorization(
    httpMethod: httpMethod,
    uri: uri,
    token: token,
    date: Date(),
    payload: payload
)

if auth = auth {
    let header = auth.getHeader()!
}
```

A trivial full example is shown as follows:

```swift
let token = Token(
    accessToken: "7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA",
    refreshToken: "7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA",
    ikm: Data(base64Encoded: "bDEyECRvKKE8w81fX4hz/52cvHsFPMGeJ+a9fGaVvWM=")!,
    signature: Data(base64Encoded: "ecYXfAwNVoS9ePn4xWhiJOdXQzr6LpJIeIn4AVju/Ug=")!,
    expiresAt: Date(timeIntervalSinceReferenceDate: 1472678411)
)

let date = Date()

let auth = try? Authorization(
    httpMethod: "POST",
    uri: "/api/v1/test",
    token: token,
    date: date,
    payload: "{\"foo\":\"bar\"}".data(using: .utf8, allowLossyConversion: false)
)

if auth = auth {
    let header = auth.getHeader()!
}
```

> Note that the `date` property should be pore-offset when calling `Authorization` to prevent time skewing.

The `payload` parameter in `Authorization:init` should be a JSON serializable string.

### Version 2 HMAC Header

The Version 2 HMAC header, for API's that support it can be retrieved by calling:

```swift
if auth = auth {
    let header = auth.getHeader()!
}
```

### Version 1 HMAC Header

For API's using version 1 of the HMAC header, call `Authorization` with the optional `version` parameter set to `1` for the 6th parameter.

```swift
let auth = try? Authorization(
    httpMethod: httpMethod,
    uri: uri,
    token: token,
    date: Date(),
    payload: payload,
    version: 1
)

if auth = auth {
    let header = auth.getHeader()!
}
```

This string can be used in the `Authorization` Header

#### Date Header

The Version 1 HMAC header requires an additional `X-Date` header. The `X-Date` header can be retrieved by calling `authorization.getDateString()`

## Encrypted Requests & Responses

This library enables clients coding in PHP 7.1+ to establish and trusted encrypted session on top of a TLS layer, while simultaniously (and independently) providing the ability authenticate and identify a client via HMAC+HKDF style authentication.

The rationale for this functionality includes but is not limited to:

1. Necessity for extra layer of security
2. Lack of trust in the network or TLS itself (see https://blog.cloudflare.com/incident-report-on-memory-leak-caused-by-cloudflare-parser-bug/)
3. Need to ensure confidentiality of the Initial Key Material (IKM) provided by the server for HMAC+HKDF authentication
4. Need to ensure confidentiality of user submitted credentials to the API for authentication

The primary reason you may want to establish an encrypted session with the API itself is to ensure confidentiality of the IKM to prevent data leakages over untrusted networks to avoid information being exposed in a Cloudflare like incident (or any man-in-the-middle attack). Encrypted sessions enable you to utilize a service like Cloudflare should a memory leak occur again with confidence that the IKM and other secure data would not be exposed.

### Encrypted Request Body

Payloads can be encrypted as follows:

```swift
```

> Note that you need to have a pre-bootstrapped public key to encrypt data. For the v1 API, this is typically this is returned by `/api/v1/server/otk`.

### Decrypting Responses

Responses from the server can be decrypted as follows:

```swift

```