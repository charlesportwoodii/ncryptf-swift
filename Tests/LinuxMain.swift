import XCTest
@testable import ncryptfTest

XCTMain([
   testCase(SignatureTest.allTests),
   testCase(AuthorizationTest.allTests)
])