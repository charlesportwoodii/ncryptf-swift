import XCTest
import Foundation
@testable import ncryptf

class SignatureTest : XCTestCase {

    static let allTests = [
        ("testV1Signatures", testV1Signatures),
        ("testV2Signatures", testV2Signatures)
    ]

    let v1SignatureResults = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b",
        "37a76343c8e3c695feeaadfe52329673ff129c65f99f55ae6056c9254f4c481d",
        "4da787ba25545ca80765298be5676370dae5db4892e9ff59511a2c13ea20c7f5",
        "9782504e91ad436a9cf456454922cfe143163a2c1361882b0dffb754638b5050",
        "69b3df79d454e1fdd375e53612c61e5e0e5deaa9e98e5746296a52c6f2bad9bb",
        "69b3df79d454e1fdd375e53612c61e5e0e5deaa9e98e5746296a52c6f2bad9bb"
    ]

    let v2SignatureResults = [
        "N1pQ53yIzsaOXB4d8eGW9NjZx7rq5LpvWMdXHjZc3szfD96u5diwFaExSa4Ze6yfC/T099OETLaffCWjMoHQzw==",
        "N1pQ53yIzsaOXB4d8eGW9NjZx7rq5LpvWMdXHjZc3szfD96u5diwFaExSa4Ze6yfC/T099OETLaffCWjMoHQzw==",
        "N1pQ53yIzsaOXB4d8eGW9NjZx7rq5LpvWMdXHjZc3szfD96u5diwFaExSa4Ze6yfC/T099OETLaffCWjMoHQzw==",
        "cH3ZMCv5+dQqFKxuSSRmVaRvAiu3QQJ75gQAE1Q+M3ZI8GcNKdHOtl86JesbP31v/m7uHsAkbDgz0BsfBHKPIA==",
        "ZZW9zm1I0rZLr7++giav+lQ59b7AoVltfqK03MJsvAKr7qPHeda0qz/nGU3pqtZgJ3VozweIrORZWIspweJc1g==",
        "Mapt8KeGXDIFFPgs7YplHmykBfm9PkD4QHq0J+ozsdtpFcX5mB8xtj0SfVsxWeWLt7Ydm3CjOqHfOh3v/wMC4A==",
        "EWE0+YqAyzIr0vbSVXHSpcn/mnWr0I2oAmJ9Med2jVW9p5NbzxbDc4AhEbTT4ha9f7RQFJI0ddY1SzK8fK8LpQ==",
        "NTNNxhPRBFJd6g5QShHG44SwuHzWN4bVsKGe1vSXOr/ugRadeA4xiLMmnWSIsql/kILH1ez/asd3Y7Yv1BOqYQ==",
        "NTNNxhPRBFJd6g5QShHG44SwuHzWN4bVsKGe1vSXOr/ugRadeA4xiLMmnWSIsql/kILH1ez/asd3Y7Yv1BOqYQ==",
    ]

    let date = Date(timeIntervalSince1970: 1533310068)
    let salt = Data(base64Encoded:"efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=")!.bytes
    let token = Token(
        accessToken: "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J",
        refreshToken: "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8",
        ikm: Data(base64Encoded:"f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=")!,
        signature: Data(base64Encoded: "waWBMawHD1zpAFRcX7e45L1aqsA3mEeSOwXqq4l1i3I=")!,
        expiresAt: Date().adding( minutes: (4 * 60)).timeIntervalSince1970
    )
    
    let testCases = [
        TestCase(httpMethod: "GET", uri: "/api/v1/test", payload: "".toData()),
        TestCase(httpMethod: "GET", uri: "/api/v1/test?foo=bar", payload: "".toData()),
        TestCase(httpMethod: "GET", uri: "/api/v1/test?foo=bar&a[a]=1", payload: "".toData()),
        TestCase(httpMethod: "POST", uri: "/api/v1/test", payload: "{\"foo\":\"bar\"}".toData()),
        TestCase(httpMethod: "POST", uri: "/api/v1/test", payload: "{\"foo\":1}".toData()),
        TestCase(httpMethod: "POST", uri: "/api/v1/test", payload: "{\"foo\":false}".toData()),
        TestCase(httpMethod: "POST", uri: "/api/v1/test", payload: "{\"foo\":1.023}".toData()),
        TestCase(httpMethod: "DELETE", uri: "/api/v1/test", payload: "{\"alpha\": [\"a\", \"b\", \"c\"],\"obj\": {\"ints\": [1, 2, 3],\"floats\": [0.0, 1.1, 1.2, 1.3],\"bools\": [true, false],\"nil\": null,\"int\": 13,\"float\": 3.1415,\"bool\": true,\"nesting\": {\"nested\": true}}}".toData()),
        TestCase(httpMethod: "DELETE", uri: "/api/v1/test?foo=bar", payload: "{\"alpha\": [\"a\", \"b\", \"c\"],\"obj\": {\"ints\": [1, 2, 3],\"floats\": [0.0, 1.1, 1.2, 1.3],\"bools\": [true, false],\"nil\": null,\"int\": 13,\"float\": 3.1415,\"bool\": true,\"nesting\": {\"nested\": true}}}".toData())
    ]

    override func setUp() {
        super.setUp() 
    }

    override func tearDown() {
        super.tearDown()
    }

    func testV1Signatures() {
        for (index, testCase) in testCases.enumerated() {
            let signature = Signature().derive(
                httpMethod: testCase.httpMethod,
                uri: testCase.uri,
                salt: salt,
                date: date,
                payload: testCase.payload!,
                version: 1
            )

            let hash = signature.lines.first!            
            XCTAssertEqual(hash, v1SignatureResults[index])
        }
    }

    func testV2Signatures() {
       for (index, testCase) in testCases.enumerated() {
            let signature = Signature().derive(
                httpMethod: testCase.httpMethod,
                uri: testCase.uri,
                salt: salt,
                date: date,
                payload: testCase.payload!,
                version: 2
            )
         
            let hash = signature.lines.first!
            XCTAssertEqual(hash, v2SignatureResults[index])
        }
    }
}