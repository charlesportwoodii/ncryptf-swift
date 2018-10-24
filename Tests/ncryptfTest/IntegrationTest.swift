import XCTest
import Foundation
import CryptoSwift
import Sodium
import Rainbow
import PerfectCURL
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
        let request = CURLRequest(
            (self.url! + "/ek"),
            .addHeader(CURLRequest.Header.Name.accept, "application/vnd.ncryptf+json"),
            .addHeader(CURLRequest.Header.Name.custom(name: "Content-Type"), "application/vnd.ncryptf+json")
        )

        if self.token != nil {
            request.addHeader(CURLRequest.Header.Name.custom(name: "X-Access-Token"), value: self.token!)
        }

        let publicKey: String = Data(
            bytes: self.key!.getPublicKey(),
            count: self.key!.getPublicKey().count
        ).base64EncodedString()
        request.addHeader(CURLRequest.Header.Name.custom(name: "x-pubkey"), value: publicKey)

        guard let response = try? request.perform() else {
            return XCTFail("Server did not provide response.")
        }

        XCTAssertEqual(200, response.responseCode)

        guard let r: Response = try? Response(secretKey: self.key!.getSecretKey()) else {
            return XCTFail("Unable to instantiate response object.")
        }

        let responseBody: Bytes = Data(base64Encoded: response.bodyString)!.bytes
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

        guard var req: Request = try? Request(
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

        let request = CURLRequest(
            (self.url! + "/echo"),
            .httpMethod(.post),
            .postString(encryptedPayload),
            .addHeader(CURLRequest.Header.Name.accept, "application/vnd.ncryptf+json"),
            .addHeader(CURLRequest.Header.Name.custom(name: "Content-Type"), "application/vnd.ncryptf+json")
        )

        if self.token != nil {
            request.addHeader(CURLRequest.Header.Name.custom(name: "X-Access-Token"), value: self.token!)
        }

        request.addHeader(CURLRequest.Header.Name.custom(name: "X-HashId"), value: stack.hashid)

        // Our public is is embedded in the signed request, so we don't need to explicitly tell
        // the server what our public key is via this header. Implementors may wish to always include this for convenience
        // If a public key is embedded in the body, it will supercede whatever is in the header.
        //request.addHeader(CURLRequest.Header.Name.custom(name: "x-pubkey"), value: publicKey)

        guard let response = try? request.perform() else {
            return XCTFail("Server did not provide response.")
        }

        XCTAssertEqual(200, response.responseCode)

        guard let r: Response = try? Response(secretKey: self.key!.getSecretKey()) else {
            return XCTFail("Unable to instantiate response object.")
        }

        let responseBody: Bytes = Data(base64Encoded: response.bodyString)!.bytes
        guard let message: Data? = try? r.decrypt(response: responseBody) else {
            return XCTFail("Unable to decrypt string.")
        }

        XCTAssertEqual(payload, message!.toString()!)
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

        guard var req: Request = try? Request(
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

        let request = CURLRequest(
            (self.url! + "/authenticate"),
            .httpMethod(.post),
            .postString(encryptedPayload),
            .addHeader(CURLRequest.Header.Name.accept, "application/vnd.ncryptf+json"),
            .addHeader(CURLRequest.Header.Name.custom(name: "Content-Type"), "application/vnd.ncryptf+json")
        )

        if self.token != nil {
            request.addHeader(CURLRequest.Header.Name.custom(name: "X-Access-Token"), value: self.token!)
        }

        request.addHeader(CURLRequest.Header.Name.custom(name: "X-HashId"), value: stack.hashid)

        // Our public is is embedded in the signed request, so we don't need to explicitly tell
        // the server what our public key is via this header. Implementors may wish to always include this for convenience
        // If a public key is embedded in the body, it will supercede whatever is in the header.
        //request.addHeader(CURLRequest.Header.Name.custom(name: "x-pubkey"), value: publicKey)

        guard let response = try? request.perform() else {
            return XCTFail("Server did not provide response.")
        }

        XCTAssertEqual(200, response.responseCode)

        guard let r: Response = try? Response(secretKey: self.key!.getSecretKey()) else {
            return XCTFail("Unable to instantiate response object.")
        }

        let responseBody: Bytes = Data(base64Encoded: response.bodyString)!.bytes
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
    }

    func testAuthenticatedEchoWithEncryptedRequest()
    {
        self.testAuthenticateWithEncryptedRequest()
        guard let stack: EKB = self.ephemeralKeyBootstrap else {
            return XCTFail("EphemeralKeyBoostrap operation failed.")
        }

        guard let t: Token = self.authToken else {
            return XCTFail("Unable to extract token from prior response.")
        }

        guard var req: Request = try? Request(
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

        let request = CURLRequest(
            (self.url! + "/echo"),
            .httpMethod(.put),
            .postString(encryptedPayload),
            .addHeader(CURLRequest.Header.Name.accept, "application/vnd.ncryptf+json"),
            .addHeader(CURLRequest.Header.Name.custom(name: "Content-Type"), "application/vnd.ncryptf+json")
        )

        if self.token != nil {
            request.addHeader(CURLRequest.Header.Name.custom(name: "X-Access-Token"), value: self.token!)
        }

        request.addHeader(CURLRequest.Header.Name.custom(name: "X-HashId"), value: stack.hashid)

        // Our public is is embedded in the signed request, so we don't need to explicitly tell
        // the server what our public key is via this header. Implementors may wish to always include this for convenience
        // If a public key is embedded in the body, it will supercede whatever is in the header.
        //request.addHeader(CURLRequest.Header.Name.custom(name: "x-pubkey"), value: publicKey)

        guard let auth: Authorization = try? Authorization(
            httpMethod: "PUT",
            uri: "/echo",
            token: t,
            date: Date(),
            payload: payload.toData()!
        ) else {
            return XCTFail("Unable to generate Authorization header.")
        }

        request.addHeader(CURLRequest.Header.Name.custom(name: "Authorization"), value: auth.getHeader()!)

        guard let response = try? request.perform() else {
            return XCTFail("Server did not provide response.")
        }

        XCTAssertEqual(200, response.responseCode)

        guard let r: Response = try? Response(secretKey: self.key!.getSecretKey()) else {
            return XCTFail("Unable to instantiate response object.")
        }

        print(response.bodyString)

        let responseBody: Bytes = Data(base64Encoded: response.bodyString)!.bytes
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

        XCTAssertEqual(payload, message!.toString()!)
    }

    /************************************************************************************************
     *
     * The requests that follow are for implementation sanity checks, and should not be referenced
     * for other client implementations
     *
     ************************************************************************************************/
    func testAuthenticatedEchoWithBadSignature()
    {
        self.testAuthenticateWithEncryptedRequest()
        guard let stack: EKB = self.ephemeralKeyBootstrap else {
            return XCTFail("EphemeralKeyBoostrap operation failed.")
        }

        guard let t: Token = self.authToken else {
            return XCTFail("Unable to extract token from prior response.")
        }

        guard var req: Request = try? Request(
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

        let request = CURLRequest(
            (self.url! + "/echo"),
            .httpMethod(.put),
            .postString(encryptedPayload),
            .addHeader(CURLRequest.Header.Name.accept, "application/vnd.ncryptf+json"),
            .addHeader(CURLRequest.Header.Name.custom(name: "Content-Type"), "application/vnd.ncryptf+json")
        )

        if self.token != nil {
            request.addHeader(CURLRequest.Header.Name.custom(name: "X-Access-Token"), value: self.token!)
        }

        request.addHeader(CURLRequest.Header.Name.custom(name: "X-HashId"), value: stack.hashid)

        // Our public is is embedded in the signed request, so we don't need to explicitly tell
        // the server what our public key is via this header. Implementors may wish to always include this for convenience
        // If a public key is embedded in the body, it will supercede whatever is in the header.
        //request.addHeader(CURLRequest.Header.Name.custom(name: "x-pubkey"), value: publicKey)

        guard let auth: Authorization = try? Authorization(
            httpMethod: "PUT",
            uri: "/echo",
            token: t,
            date: Date(),
            payload: payload.toData()!
        ) else {
            return XCTFail("Unable to generate Authorization header.")
        }

        request.addHeader(CURLRequest.Header.Name.custom(name: "Authorization"), value: auth.getHeader()!)

        guard let response = try? request.perform() else {
            return XCTFail("Server did not provide response.")
        }

        XCTAssertEqual(401, response.responseCode)
    }

    func testMalformedEncryptedRequest()
    {

    }
}