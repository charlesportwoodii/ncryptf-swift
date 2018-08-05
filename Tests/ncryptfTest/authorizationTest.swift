import XCTest
import ncrypptf
import Foundation

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

class ncryuptfTest: XCTestCase {

    static let allTests = [
    ]

    let token = ncryptf.createToken(
        accessToken: "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J",
        refreshToken: "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8",
        ikm: Data(base64Encoded:"f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=")!,
        signature: Data(base64Encoded: "waWBMawHD1zpAFRcX7e45L1aqsA3mEeSOwXqq4l1i3I=")!,
        expiresAt: Date().timeIntervalSince1970 + (60 * 60 * 60)
    )
}
