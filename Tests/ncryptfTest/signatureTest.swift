import XCTest
import Foundation
import Sodium
import ncryptf

extension String {
    func toData() -> Data? {
        return self.data(using: .utf8, allowLossyConversion: false)
    }
}

extension Data {
    func toString() -> String? {
        return String(data: self, encoding: .utf8)
    }
}

public struct signatureTest {
    public let httpMethod: String
    public let uri: String
    public let salt: Bytes?
    public let date: Date
    public let payload: Data?
    public let v1SignatureString: Data?
    public let v2SignatureString: Data?
}

class signatureTest: XCTestCase {

    static let allTests = [
        ("testTokenIsNotExpired", testTokenIsNotExpired),
        ("testTokenIkmIs32Bytes", testTokenIkmIs32Bytes)
    ]

    static let complexJson = "{\"alpha\": [\"a\", \"b\", \"c\"],\"obj\": {\"ints\": [1, 2, 3],\"floats\": [1.1, 1.2, 1.3],\"bools\": [true, false],\"nil\": null,\"int\": 13,\"float\": 3.1415,\"bool\": true,\"nesting\": {\"nested\": true}}}".data(using: .utf8)
    static let dateString = "Fri, 03 Aug 2018 15:27:48 +0000"
    static let date = Date(timeIntervalSinceReferenceDate: 1533310068)

    static let salt = Data(base64Encoded:"efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=")
    static let signatureTestCases = [
        "emptyGet": signatureTest("GET", "/api/v1/test", salt!.bytes, date, "".data(using: .utf8)
        "emptyGetWithQueryParam": signatureTest("GET", "/api/v1/test?foo=bar", salt!.bytes, date, "".data(using: .utf8)
        "emptyGetWithChainedQueryParam": signatureTest("GET", "/api/v1/test?foo=bar&a[a]=1", salt!.bytes, date, "".data(using: .utf8)
        "postWithStringObjKeys": signatureTest("POST", "/api/v1/test", salt.bytes, date, "{ \"foo\": \"bar\"}".data(using: .utf8)
        "postWithIntValue": signatureTest("POST", "/api/v1/test", salt.bytes, date, "{ \"foo\": 1 }".data(using: .utf8)
        "postWithBooleanValue": signatureTest("POST", "/api/v1/test", salt.bytes, date, "{ \"foo\": false }".data(using: .utf8)
        "postWithFloatingPointValue": signatureTest("POST", "/api/v1/test", salt.bytes, date, "{ \"foo\": 1.023 }".data(using: .utf8)
        "deleteWithComplexValue": signatureTest("POST", "/api/v1/test", salt.bytes, date, complexJson
        "deleteWithComplexValueAndQueryString": signatureTest("POST", "/api/v1/test?foo=bar", salt.bytes, date, complexJson
    ]

    static let token = ncryptf.createToken(
        accessToken: "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J",
        refreshToken: "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8",
        ikm: Data(base64Encoded:"f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=")!,
        signature: Data(base64Encoded: "waWBMawHD1zpAFRcX7e45L1aqsA3mEeSOwXqq4l1i3I=")!,
        expiresAt: Date().timeIntervalSince1970 + (60 * 60 * 60)
    )

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testTokenIsNotExpired() {
        XCTAssertEqual(token.isExpired(), false)
    }

    func testTokenIkmIs32Bytes() {
        XCTAssertEqual(token.ikm.count, 32)
    }
}
