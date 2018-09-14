import XCTest
import Foundation
import CryptoSwift

@testable import ncryptf

class RequestResponseTest : XCTestCase {
    static let allTests = [
        ("testv1EncryptDecrypt", testv1EncryptDecrypt),
        ("testv2EncryptDecrypt", testv2EncryptDecrypt)
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

    let expectedv2Cipher = Data(base64Encoded: "3iWQAm7pUZyrfwb8J8IgjAS73UTOfsjRT9/FLTo569CkMuhiesfnkGvsDcHR3o2aPL2OVTcmWOTX8AY11odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0i42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsXXLyXJTMRMe6XFv43lZtJhRxsVZLGOodP7zZGU31X/sH7aH5z/sgxXazbOU7WfhUNChDpuppvV1DF2ry2lPcg4SwqYwa53inoY2+eCPP4Hkp/PKhSOEMFlWV+dlQirn6GGf5RQSsQ7ti/QCvi/BRIhb3ZHiPptZJZIbYwqIpvYu")!.bytes
    
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

    func testv2EncryptDecrypt()
    {
        var request = Request(
            secretKey: clientKeyPairSecret,
            publicKey: serverKeyPairPublic
        )

        let cipher = try! request.encrypt(
            request: payload.toData()!,
            signatureKey: signatureKeyPairSecret,
            nonce: nonce
        )

        XCTAssertEqual(cipher!, expectedv2Cipher);

        var response = Response(
            secretKey: serverKeyPairSecret
        )

        let decrypted = try! response.decrypt(
            response: cipher!
        )

        XCTAssertEqual(payload.toData()!, decrypted)
    }

    func testv1EncryptDecrypt()
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

        var response = Response(
            secretKey: serverKeyPairSecret,
            publicKey: clientKeyPairPublic
        )

        let decrypted = try! response.decrypt(
            response: cipher!,
            nonce: nonce
        )

        XCTAssertEqual(payload.toData()!, decrypted)
        
        let isSignatureValid = response.isSignatureValid(
            response: payload.toData()!.bytes,
            signature: signature!,
            publicKey: signatureKeyPairPublic
        )

        XCTAssert(isSignatureValid)
    }
}