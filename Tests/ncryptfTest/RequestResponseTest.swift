import XCTest
import Foundation
import CryptoSwift
@testable import ncryptf

class RequestResponseTest : XCTestCase {
    static let allTests = [
        ("testEncryptDecrypt", testEncryptDecrypt)
    ]

    let clientKeyPairSecret = Data(base64Encoded: "bvV/vnfB43spmprI8aBK/Fd8xxSBlx7EhuxfxxTVI2o=")!.bytes
    let clientKeyPairPublic = Data(base64Encoded: "Ojnr0KQy6GJ6x+eQa+wNwdHejZo8vY5VNyZY5NfwBjU=")!.bytes
    
    let serverKeyPairSecret = Data(base64Encoded: "gH1+ileX1W5fMeOWue8HxdREnK04u72ybxCQgivWoZ4=")!.bytes
    let serverKeyPairPublic = Data(base64Encoded: "YU74X2OqHujLVDH9wgEHscD5eyiLPvcugRUZG6R3BB8=")!.bytes

    let signatureKeyPairSecret = Data(base64Encoded: "9wdUWlSW2ZQB6ImeUZ5rVqcW+mgQncN1Cr5D2YvFdvEi42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsQ==")!.bytes
    let signatureKeyPairPublic = Data(base64Encoded: "IuNjSiv+ueMxrcU0jnDRzxMLRQM9AOJNIcJSBaKWRLE=")!.bytes

    let nonce = Data(base64Encoded: "bulRnKt/BvwnwiCMBLvdRM5+yNFP38Ut")!.bytes

    let payload = """
{
    "foo": "bar",
    "test": {
        "true": false,
        "zero": 0.0,
        "a": 1,
        "b": 3.14,
        "nil": null,
        "arr": [
            "a", "b", "c", "d"
        ]
    }
}
"""

    override func setUp() {
        super.setUp() 
    }

    override func tearDown() {
        super.tearDown()
    }

    func testEncryptDecrypt()
    {
        var request = Request(
            secretKey: clientKeyPairSecret,
            publicKey: serverKeyPairPublic
        )

        let cipher = try! request.encrypt(
            request: payload.toData()!,
            nonce: nonce
        )

        let signature = try! request.sign(
            request: payload.toData()!,
            secretKey: signatureKeyPairSecret
        )

        let response = Response(
            secretKey: serverKeyPairSecret,
            publicKey: clientKeyPairPublic
        )

        let decrypted = try! response.decrypt(
            response: cipher!,
            nonce: nonce
        )

        XCTAssertEqual(payload.toData()!, decrypted)
        
        let isSignatureValid = try! response.isSignatureValid(
            response: payload.toData()!.bytes,
            signature: signature!,
            publicKey: signatureKeyPairPublic
        )

        XCTAssert(isSignatureValid)
    }
}