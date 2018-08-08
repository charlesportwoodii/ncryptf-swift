import Foundation
import Sodium

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

public struct sig {
    public let httpMethod: String
    public let uri: String
    public let salt: Bytes
    public let date: Date
    public let payload: Data
}