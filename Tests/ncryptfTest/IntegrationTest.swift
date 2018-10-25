import XCTest
import Foundation
import CryptoSwift
import Sodium
import Rainbow
import Alamofire
@testable import ncryptf

internal struct EKB: Codable {
    let key: Bytes
    let hashid: String
}

internal struct Boostrap: Codable {
    enum CodingKeys: String, CodingKey {
        case pk = "public"
        case signature
        case hashid = "hash-id"
    }

    let pk: String
    let signature: String
    let hashid: String
}

internal struct AuthResponse: Codable {
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case ikm
        case signing
        case expiresAt = "expires_at"
    }

    let accessToken: String
    let refreshToken: String
    let ikm: String
    let signing: String
    let expiresAt: Double
}

/**
  This class demonstrates a practical end-to-end implementation via cURL
  Implementation may be inferred from this implementation, and is broken out into the following stages:
  1. Create a com.ncryptf.android.Keypair instance
  2. Bootstrap an encrypted session by sending an unauthenticated requests to the ephemeral key endpoint with the following headers:
   - Accept: application/vnd.ncryptf+json
   - Content-Type: application/vnd.ncryptf+json
   - X-PubKey: <base64_encoded_$key->getPublicKey()>
  3. Decrypt the V2 response from the server. This contains a single use ephemeral key we can use to encrypt future requests in the payload.
     The servers public key is embedded in the response, and can be extracted by `Response::getPublicKeyFromResponse($response);`
  4. Perform an authenticated request using the clients secret key, and the servers public key.


  Implementation Details
  - The server WILL always advertise at minimum the following 2 headers:
       - X-HashId: A string used to represent the identifier to use to select which key to use.
       - X-Public-Key-Expiration: A unix timestamp representing the time at which the key will expire. This is used to determine if rekeying is required.
  - The server WILL always generate a new keypair for each request. You may continue to use existing keys until they expire.
  - To achieve perfect-forward-secrecy, it is advised to rekey the client key on each request. The server does not store the shared secret for prior requests.
  - The client SHOULD keep a record of public keys offered by the server, along with their expiration time.
  - The client SHOULD always use the most recent key offered by the server.
  - If the client does not have any active keys, it should bootstrap a new session by calling the ephemeral key endpoint to retrieve a new public key from the server.
 */
class IntegrationTest : XCTestCase {
    static let allTests = [
        ("testEphemeralKeyBootstrap", testEphemeralKeyBootstrap),
        ("testUnauthenticatedEncryptedRequest", testUnauthenticatedEncryptedRequest),
        ("testAuthenticateWithEncryptedRequest", testAuthenticateWithEncryptedRequest),
        ("testAuthenticatedEchoWithEncryptedRequest", testAuthenticatedEchoWithEncryptedRequest),
        ("testAuthenticatedEchoWithBadSignature", testAuthenticatedEchoWithBadSignature),
        ("testMalformedEncryptedRequest", testMalformedEncryptedRequest)
    ]

    private var url: String? = nil
    private var key: Keypair? = nil
    private var token: String? = nil
    private var ephemeralKeyBootstrap: EKB? = nil
    private var authToken: Token? = nil

    /**
     Overwrites the tests so that if `NCRYPTF_TEST_API` environment variable isn't set all tests
     in this class are skipped.

     This also handles definition of all environment variables
     */
    override func invokeTest() {
        #if os(Linux)
            print("This test cannot run on Linux, skipping ---".yellow)
        #endif

        let environment = ProcessInfo().environment
        if let url = environment["NCRYPTF_TEST_API"] {
            self.url = url
        } else {
            print("NCRYPTF_TEST_API environment variable is not defined, skipping ---".yellow)
            return
        }

        if let token = environment["ACCESS_TOKEN"] {
            self.token = token
        } else {
            print("ACCESS_TOKEN environment variable is not defined.".yellow)
        }

        super.invokeTest()
    }

    /**
     Creates a new keypair
     */
    override func setUp() {
        super.setUp()
        self.key = try! Utils.generateKeypair()
    }

    override func tearDown() {
        super.tearDown()
    }

    /**
     Tests the bootstrap process with an encrypted response
     */
    func testEphemeralKeyBootstrap()
    {
        let e = expectation(description: "Alamofire")

        var headers: HTTPHeaders = [
            "Accept": "application/vnd.ncryptf+json",
            "Content-Type": "application/vnd.ncryptf+json"
        ]

        if self.token != nil {
            headers["X-Access-Token"] = self.token!
        }

        let publicKey: String = Data(
            bytes: self.key!.getPublicKey(),
            count: self.key!.getPublicKey().count
        ).base64EncodedString()

        headers["x-pubkey"] = publicKey

        let request = Alamofire.request(
            self.url! + "/ek",
            headers: headers
        )

        request.responseString { response in
            XCTAssertEqual(200, response.response?.statusCode)

            guard let r: Response = try? Response(secretKey: self.key!.getSecretKey()) else {
                return XCTFail("Unable to instantiate response object.")
            }

            let responseBody: Bytes = Data(base64Encoded: response.result.value!)!.bytes
            guard let message: Data? = try? r.decrypt(response: responseBody) else {
                return XCTFail("Unable to decrypt string.")
            }

            let decoder = JSONDecoder()
            guard let json = try? decoder.decode(
                Boostrap.self,
                from: message!
            ) else {
                return XCTFail("JSON parsing failed")
            }

            XCTAssertNotNil(json)
            XCTAssertNotNil(json.pk)
            XCTAssertNotNil(json.hashid)
            XCTAssertNotNil(json.signature)

            self.ephemeralKeyBootstrap = EKB(key: Data(base64Encoded: json.pk)!.bytes, hashid: json.hashid)
            e.fulfill()
        }
        waitForExpectations(timeout: 5.0, handler: nil)
    }

    /**
     This test illustrates making an unauthenticated encrypted request and receiving an encrypted response back
     */
    func testUnauthenticatedEncryptedRequest()
    {
        self.testEphemeralKeyBootstrap()
        guard let stack: EKB = self.ephemeralKeyBootstrap else {
            return XCTFail("EphemeralKeyBoostrap operation failed.")
        }

        let e = expectation(description: "Alamofire")

        var headers: HTTPHeaders = [
            "Accept": "application/vnd.ncryptf+json",
            "Content-Type": "application/vnd.ncryptf+json"
        ]

        if self.token != nil {
            headers["X-Access-Token"] = self.token!
        }

        // Our public is is embedded in the signed request, so we don't need to explicitly tell
        // the server what our public key is via this header. Implementors may wish to always include this for convenience
        // If a public key is embedded in the body, it will supercede whatever is in the header.
        //headers["x-pubkey"] = publicKey
        headers["X-HashId"] = stack.hashid

        guard var req: ncryptf.Request = try? ncryptf.Request(
            secretKey: self.key!.getSecretKey(),
            signatureSecretKey: try! Utils.generateSigningKeypair().getSecretKey()
        ) else {
            return XCTFail("Unable to create encrypted request.")
        }

        let payload: String = "{\"hello\":\"world\"}"
        guard let encrypted : Bytes? = try? req.encrypt(
            request: payload.toData()!,
            publicKey: stack.key
        ) else {
            return XCTFail("Unable to encrypt payload.")
        }

        let encryptedPayload: String = Data(
            bytes: encrypted!,
            count: encrypted!.count
        ).base64EncodedString()

        let request = Alamofire.request(
            self.url! + "/echo",
            method: .post,
            parameters: [:],
            encoding: encryptedPayload,
            headers: headers
        )

        request.responseString { response in
            XCTAssertEqual(200, response.response?.statusCode)

            guard let r: Response = try? Response(secretKey: self.key!.getSecretKey()) else {
                return XCTFail("Unable to instantiate response object.")
            }

            let responseBody: Bytes = Data(base64Encoded: response.result.value!)!.bytes
            guard let message: Data? = try? r.decrypt(response: responseBody) else {
                return XCTFail("Unable to decrypt string.")
            }

            XCTAssertEqual(payload, message!.toString()!)
            e.fulfill()
        }

        waitForExpectations(timeout: 5.0, handler: nil)
    }

    /**
     This request securely authenticates a user with an encrypted request and returns an encrypted response
     This request is encrypted end-to-end
     */
    func testAuthenticateWithEncryptedRequest()
    {
        self.testEphemeralKeyBootstrap()
        guard let stack: EKB = self.ephemeralKeyBootstrap else {
            return XCTFail("EphemeralKeyBoostrap operation failed.")
        }

        let e = expectation(description: "Alamofire")

        var headers: HTTPHeaders = [
            "Accept": "application/vnd.ncryptf+json",
            "Content-Type": "application/vnd.ncryptf+json"
        ]

        if self.token != nil {
            headers["X-Access-Token"] = self.token!
        }

        // Our public is is embedded in the signed request, so we don't need to explicitly tell
        // the server what our public key is via this header. Implementors may wish to always include this for convenience
        // If a public key is embedded in the body, it will supercede whatever is in the header.
        //headers["x-pubkey"] = publicKey
        headers["X-HashId"] = stack.hashid

        guard var req: ncryptf.Request = try? ncryptf.Request(
            secretKey: self.key!.getSecretKey(),
            signatureSecretKey: try! Utils.generateSigningKeypair().getSecretKey()
        ) else {
            return XCTFail("Unable to create encrypted request.")
        }

        let payload: String = "{\"email\":\"clara.oswald@example.com\",\"password\":\"c0rect h0rs3 b@tt3y st@Pl3\"}"
        guard let encrypted : Bytes? = try? req.encrypt(
            request: payload.toData()!,
            publicKey: stack.key
        ) else {
            return XCTFail("Unable to encrypt payload.")
        }

        let encryptedPayload: String = Data(
            bytes: encrypted!,
            count: encrypted!.count
        ).base64EncodedString()

        let request = Alamofire.request(
            self.url! + "/authenticate",
            method: .post,
            parameters: [:],
            encoding: encryptedPayload,
            headers: headers
        )

        request.responseString { response in
            XCTAssertEqual(200, response.response?.statusCode)

            guard let r: Response = try? Response(secretKey: self.key!.getSecretKey()) else {
                return XCTFail("Unable to instantiate response object.")
            }

            let responseBody: Bytes = Data(base64Encoded: response.result.value!)!.bytes
            guard let message: Data? = try? r.decrypt(response: responseBody) else {
                return XCTFail("Unable to decrypt string.")
            }

            let decoder = JSONDecoder()
            guard let json = try? decoder.decode(
                AuthResponse.self,
                from: message!
            ) else {
                return XCTFail("JSON parsing failed")
            }

            XCTAssertNotNil(json)
            XCTAssertNotNil(json.accessToken)
            XCTAssertNotNil(json.refreshToken)
            XCTAssertNotNil(json.ikm)
            XCTAssertNotNil(json.signing)
            XCTAssertNotNil(json.expiresAt)

            guard let t: Token = try? Token(
                accessToken: json.accessToken,
                refreshToken: json.refreshToken,
                ikm: Data(base64Encoded: json.ikm)!,
                signature:  Data(base64Encoded: json.signing)!,
                expiresAt: json.expiresAt
            ) else {
                return XCTFail("Unable to generate ncryptf Token.")
            }

            self.authToken = t
            e.fulfill()
        }

        waitForExpectations(timeout: 5.0, handler: nil)
    }

    /**
     This test performs an authenticated encrypted request and decrypts an encrypted response
     */
    func testAuthenticatedEchoWithEncryptedRequest()
    {
        self.testAuthenticateWithEncryptedRequest()
        guard let stack: EKB = self.ephemeralKeyBootstrap else {
            return XCTFail("EphemeralKeyBoostrap operation failed.")
        }

        guard let t: Token = self.authToken else {
            return XCTFail("Unable to extract token from prior response.")
        }

        let e = expectation(description: "Alamofire")

        var headers: HTTPHeaders = [
            "Accept": "application/vnd.ncryptf+json",
            "Content-Type": "application/vnd.ncryptf+json"
        ]

        if self.token != nil {
            headers["X-Access-Token"] = self.token!
        }

        // Our public is is embedded in the signed request, so we don't need to explicitly tell
        // the server what our public key is via this header. Implementors may wish to always include this for convenience
        // If a public key is embedded in the body, it will supercede whatever is in the header.
        //headers["x-pubkey"] = publicKey
        headers["X-HashId"] = stack.hashid

        guard var req: ncryptf.Request = try? ncryptf.Request(
            secretKey: self.key!.getSecretKey(),
            signatureSecretKey: t.signature
        ) else {
            return XCTFail("Unable to create encrypted request.")
        }

        let payload: String = "{\"hello\":\"world\"}"
        guard let encrypted : Bytes? = try? req.encrypt(
            request: payload.toData()!,
            publicKey: stack.key
        ) else {
            return XCTFail("Unable to encrypt payload.")
        }

        let encryptedPayload: String = Data(
            bytes: encrypted!,
            count: encrypted!.count
        ).base64EncodedString()

        guard let auth: Authorization = try? Authorization(
            httpMethod: "PUT",
            uri: "/echo",
            token: t,
            date: Date(),
            payload: payload.toData()!
        ) else {
            return XCTFail("Unable to generate Authorization header.")
        }

        headers["Authorization"] = auth.getHeader()!

        let request = Alamofire.request(
            self.url! + "/echo",
            method: .put,
            parameters: [:],
            encoding: encryptedPayload,
            headers: headers
        )

        request.responseString { response in
            XCTAssertEqual(200, response.response?.statusCode)

            guard let r: Response = try? Response(secretKey: self.key!.getSecretKey()) else {
                return XCTFail("Unable to instantiate response object.")
            }

            let responseBody: Bytes = Data(base64Encoded: response.result.value!)!.bytes
            guard let message: Data? = try? r.decrypt(response: responseBody) else {
                return XCTFail("Unable to decrypt string.")
            }

            /**
             * As an added integrity check, the API will sign the message with the same key it issued during authentication
             * Therefore, we can verify that the signing public key associated to the message matches the public key from the
             * token we were issued.
             *
             * If the keys match, then we have assurance that the message is authenticated
             * If the keys don't match, then the request has been tampered with and should be discarded.
             *
             * This check should ALWAYS be performed for authenticated requests as it ensures the validity of the message
             * and the origin of the message.
             */
            let sodium = Sodium()

            if (!sodium.utils.equals(
                t.getSignaturePublicKey()!,
                try! ncryptf.Response.getSigningPublicKeyFromResponse(response: responseBody)!
            )) {
                return XCTFail("Signature public key mismatch")
            }
            XCTAssertEqual(payload, message!.toString()!)

            e.fulfill()
        }

        waitForExpectations(timeout: 5.0, handler: nil)
    }

    /************************************************************************************************
     *
     * The requests that follow are for implementation sanity checks, and should not be referenced
     * for other client implementations
     *
     ************************************************************************************************/

    /**
     This test verifies that authenticated requests requires a signature by the API issued
     signature key instead of a randomly generated one.
     */
    func testAuthenticatedEchoWithBadSignature()
    {
        self.testAuthenticateWithEncryptedRequest()
        guard let stack: EKB = self.ephemeralKeyBootstrap else {
            return XCTFail("EphemeralKeyBoostrap operation failed.")
        }

        guard let t: Token = self.authToken else {
            return XCTFail("Unable to extract token from prior response.")
        }

        let e = expectation(description: "Alamofire")

        var headers: HTTPHeaders = [
            "Accept": "application/vnd.ncryptf+json",
            "Content-Type": "application/vnd.ncryptf+json"
        ]

        if self.token != nil {
            headers["X-Access-Token"] = self.token!
        }

        // Our public is is embedded in the signed request, so we don't need to explicitly tell
        // the server what our public key is via this header. Implementors may wish to always include this for convenience
        // If a public key is embedded in the body, it will supercede whatever is in the header.
        //headers["x-pubkey"] = publicKey
        headers["X-HashId"] = stack.hashid

        guard var req: ncryptf.Request = try? ncryptf.Request(
            secretKey: self.key!.getSecretKey(),
            signatureSecretKey: Utils.generateSigningKeypair().getSecretKey()
        ) else {
            return XCTFail("Unable to create encrypted request.")
        }

        let payload: String = "{\"hello\":\"world\"}"
        guard let encrypted : Bytes? = try? req.encrypt(
            request: payload.toData()!,
            publicKey: stack.key
        ) else {
            return XCTFail("Unable to encrypt payload.")
        }

        let encryptedPayload: String = Data(
            bytes: encrypted!,
            count: encrypted!.count
        ).base64EncodedString()

        guard let auth: Authorization = try? Authorization(
            httpMethod: "PUT",
            uri: "/echo",
            token: t,
            date: Date(),
            payload: payload.toData()!
        ) else {
            return XCTFail("Unable to generate Authorization header.")
        }

        headers["Authorization"] = auth.getHeader()!

        let request = Alamofire.request(
            self.url! + "/echo",
            method: .put,
            parameters: [:],
            encoding: encryptedPayload,
            headers: headers
        )

        request.responseString { response in
            XCTAssertEqual(401, response.response?.statusCode)
            e.fulfill()
        }

        waitForExpectations(timeout: 5.0, handler: nil)
    }

    /**
     This test verifies that a malformed payload is rejected by the API
    */
    func testMalformedEncryptedRequest()
    {
        self.testAuthenticateWithEncryptedRequest()
        guard let stack: EKB = self.ephemeralKeyBootstrap else {
            return XCTFail("EphemeralKeyBoostrap operation failed.")
        }

        guard let t: Token = self.authToken else {
            return XCTFail("Unable to extract token from prior response.")
        }

        let e = expectation(description: "Alamofire")

        var headers: HTTPHeaders = [
            "Accept": "application/vnd.ncryptf+json",
            "Content-Type": "application/vnd.ncryptf+json"
        ]

        if self.token != nil {
            headers["X-Access-Token"] = self.token!
        }

        // Our public is is embedded in the signed request, so we don't need to explicitly tell
        // the server what our public key is via this header. Implementors may wish to always include this for convenience
        // If a public key is embedded in the body, it will supercede whatever is in the header.
        //headers["x-pubkey"] = publicKey
        headers["X-HashId"] = stack.hashid

        guard var req: ncryptf.Request = try? ncryptf.Request(
            secretKey: self.key!.getSecretKey(),
            signatureSecretKey: Utils.generateSigningKeypair().getSecretKey()
        ) else {
            return XCTFail("Unable to create encrypted request.")
        }

        let payload: String = "{\"hello\":\"world\"}"
        guard let encrypted : Bytes? = try? req.encrypt(
            request: payload.toData()!,
            publicKey: stack.key
        ) else {
            return XCTFail("Unable to encrypt payload.")
        }

        // Zero a 32 byte segment to corrupt the payload
        var dEncrypted = encrypted!
        for i in 60..<92 {
            dEncrypted[i] = UInt8(0)
        }

        let encryptedPayload: String = Data(
            bytes: dEncrypted,
            count: dEncrypted.count
        ).base64EncodedString()

        guard let auth: Authorization = try? Authorization(
            httpMethod: "PUT",
            uri: "/echo",
            token: t,
            date: Date(),
            payload: payload.toData()!
        ) else {
            return XCTFail("Unable to generate Authorization header.")
        }

        headers["Authorization"] = auth.getHeader()!

        let request = Alamofire.request(
            self.url! + "/echo",
            method: .put,
            parameters: [:],
            encoding: encryptedPayload + "BABAC",
            headers: headers
        )

        request.responseString { response in
            XCTAssertEqual(400, response.response?.statusCode)
            e.fulfill()
        }

        waitForExpectations(timeout: 5.0, handler: nil)
    }
}