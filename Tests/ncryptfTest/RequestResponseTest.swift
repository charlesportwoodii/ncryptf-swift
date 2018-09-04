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

    let expectedCipher = Data(base64Encoded: "1odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0=")!.bytes
    let expectedSignature = Data(base64Encoded: "dcvJclMxEx7pcW/jeVm0mFHGxVksY6h0/vNkZTfVf+wftofnP+yDFdrNs5TtZ+FQ0KEOm6mm9XUMXavLaU9yDg==")!.bytes

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

        XCTAssertEqual(cipher!, expectedCipher);
        XCTAssertEqual(signature!, expectedSignature);

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