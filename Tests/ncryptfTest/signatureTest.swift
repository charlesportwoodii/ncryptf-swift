import XCTest
import Foundation
import Sodium
@testable import ncryptf

final class SignatureTest: XCTestCase {

    static let allTests = [
        ("testTokenIsNotExpired", testTokenIsNotExpired),
        ("testTokenIkmIs32Bytes", testTokenIkmIs32Bytes)
    ]

    static let complexJson = "{\"alpha\": [\"a\", \"b\", \"c\"],\"obj\": {\"ints\": [1, 2, 3],\"floats\": [1.1, 1.2, 1.3],\"bools\": [true, false],\"nil\": null,\"int\": 13,\"float\": 3.1415,\"bool\": true,\"nesting\": {\"nested\": true}}}".data(using: .utf8)
    static let dateString = "Fri, 03 Aug 2018 15:27:48 +0000"
    static let date = Date(timeIntervalSinceReferenceDate: 1533310068)

    static let salt = Data(base64Encoded:"efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=")

    let token = ncryptf.createToken(
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
