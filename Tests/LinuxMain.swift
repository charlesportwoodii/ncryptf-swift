import XCTest
@testable import ncryptfTest
@testable import signatureTest
@testable import authorizationTest

XCTMain([
    testCase(ncryptfTest.allTests),
    testCase(signatureTest.allTests),
    testcase(authorizationTests.allTests)
])