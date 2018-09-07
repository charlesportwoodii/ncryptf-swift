import XCTest
import Foundation
import Sodium
import CryptoSwift
@testable import ncryptf

class UtilsTest : XCTestCase {

    static let allTests = [
        ("testKeypairGeneration", testKeypairGeneration),
        ("testSigningKeypairGeneration", testSigningKeypairGeneration),
        ("testZero", testZero)
    ]

    override func setUp() {
        super.setUp() 
    }

    override func tearDown() {
        super.tearDown()
    }

    func testKeypairGeneration() {
        let kp = ncryptf.Utils.generateKeypair()
        XCTAssertEqual(32, kp.getPublicKey().count)
        XCTAssertEqual(32, kp.getSecretKey().count)
    }

    func testSigningKeypairGeneration() {
        let kp = ncryptf.Utils.generateSigningKeypair()
        XCTAssertEqual(32, kp.getPublicKey().count)
        XCTAssertEqual(64, kp.getSecretKey().count)
    }

    func testZero() {
        let sodium = Sodium()
        var bytes = sodium.randomBytes.buf(length: 32)!

        let result = Utils.zero(&bytes)
        XCTAssert(result)
        for i in 0..<bytes.count {
            XCTAssertEqual(0, bytes[i])
        }
    }
}