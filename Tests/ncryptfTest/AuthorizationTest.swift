import XCTest
import Foundation
import CryptoSwift
@testable import ncryptf

class AuthorizationTest : XCTestCase {

    static let allTests = [
        ("testV1HMAC", testV1HMAC),
        ("testV2HMAC", testV2HMAC)
    ]

    let v1HMACHeaders = [
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,26TEEe+mUjhYmgXRcy4nL+awe6ksdahhjzujFo1B4UM=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,sdDSnLvddq6IBTv0H/o4hY4u9GFzLrgP5fL0NqFxz5A=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,1g+EfJQ2JnxxVeUfUINhweftK2gCqYpMtPuJ+rc6P4A=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,Tb4/56uZ7FDtBHAbwCgYFirrXW0uhkSRFjLOZYrpHdE=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,bxbitvadJE2APYi3rid3e5SM99X2urjl1vefvZeFGeI=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,O9BUjVPYZ4zE7rlaE2C5Qt0pAa8orAJhLbxIIxV66TU=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,38TB5rfmBJ+NhxQn1lWCeG4aseFuXUthwNz61WlsjIQ=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,2wECEgRUOq1B6v8p9t1qHQME53HQfAMpjS38qI6S01M=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,ddzN/izj4XNxKx/CkZAw9uB0SXDNmxPo1zC0wgQIcrM=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
    ]

    let v2HMACHeaders = [
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiaTZHQzFtZUtWQ3VhQTYzXC9FcXBUazVYZ2VEY3pvY0ErMWxUdE5STWhLcDQ9Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiVFErejZKbzYyeDBLV0lKcjhZSzE1c1J5ZjExc09cL3daVFFhMGRBa0toT1k9Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiXC9cL21uOExkTnhIU2hlVXkwVVVLd0VGRUxwVituVVNid2l6Y3BZUkNOM29ZPSIsInNhbHQiOiJlZkVZXC9JSmRBYmk0NzRUdFFDQ2pqMnkxRkdCNEJGRlBwYkhtXC8xUXRweUk9IiwidiI6Mn0=",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiY3I1TCsxR0hGeEdIVXV2VFJjVHdCNmJzKzk5ZmNEUDhWZTk2R29NTERtaz0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoieUVSUWpsWFgyU29CTVVpeEsydU9LeUZMSDZWeDdob2E4MHdZOXJiRDlucz0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiaUx0c0poT25hWkxIbTgrYU9SWTBzUlFrRjdnVmRxaVFKTzVcL0NYRUQrck09Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiS0xlWkVJK1R3Qk16ZXBxTGNqXC91anFYcVhEZUFhUndvbmxPcU9XYjZjT2M9Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoidElsRW1vdDNGNm50UzdMRTdWa21BN0hNRVFpenBndVZXZm9MUXY2bnlWbz0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiNGlNUDZUMGFVekpwbHczK2IzQUxnMGZBVEtxcHdFUHZrNGcyRDN1bjdxVT0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9",
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

    func testV1HMAC() {
        for (index, testCase) in testCases.enumerated() {
            let auth = try? Authorization(
                httpMethod: testCase.httpMethod,
                uri: testCase.uri,
                token: token,
                date: date,
                payload: testCase.payload!,
                version: 1,
                salt: salt
            )

            XCTAssertNotNil(auth)
            if let auth = auth {
                XCTAssertEqual(auth.getHeader()!, v1HMACHeaders[index])
            } else {
                XCTFail()
            }
        }
    }

    func testV2HMAC() {
        for (index, testCase) in testCases.enumerated() {
            let auth = try? Authorization(
                httpMethod: testCase.httpMethod,
                uri: testCase.uri,
                token: token,
                date: date,
                payload: testCase.payload!,
                version: 2,
                salt: salt
            )

            XCTAssertNotNil(auth)
            if let auth = auth {
                XCTAssertEqual(auth.getHeader()!, v2HMACHeaders[index])
            } else {
                XCTFail()
            }
        }
    }
}