import XCTest
@testable import ncryptfTest

XCTMain([
   testCase(SignatureTest.allTests),
   testCase(AuthorizationTest.allTests),
   testCase(RequestResponseTest.allTests),
   testCase(UtilsTest.allTests)
   testCase(IntegrationTest.allTests)
])