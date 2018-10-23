import XCTest
import Foundation
import CryptoSwift
import Alamofire
import Sodium
import Rainbow
@testable import ncryptf

internal struct EKB: Codable {
    let key: Bytes
    let hashid: String
}

class Integrationtest : XCTestCase {
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

    override func setUp() {
        super.setUp()
        self.key = try! Utils.generateKeypair()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testEphemeralKeyBootstrap() {}
    func testUnauthenticatedEncryptedRequest() {}
    func testAuthenticateWithEncryptedRequest() {}
    func testAuthenticatedEchoWithEncryptedRequest() {}

    /************************************************************************************************
     *
     * The requests that follow are for implementation sanity checks, and should not be referenced
     * for other client implementations
     *
     ************************************************************************************************/
    func testAuthenticatedEchoWithBadSignature() {}
    func testMalformedEncryptedRequest() {}

}