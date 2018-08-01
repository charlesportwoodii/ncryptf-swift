import Foundation
import Sodium
import CryptoSwift

public struct Signature {
    public let saltBytes = Int(32)
    private let sodium = Sodium()
}

extension Signature {

    /**
        Derives a signature for hashing
            - parameters:
                - method: The HTTP method
                - uri: The URI of the request
                - bytes: The salt bytes
                - date: The date
                - data: The encoded data
            - Returns: The signature string
    */
    public func derive(method: String, uri: String, salt: Bytes, date: Date, payload: Data) -> String {
        
        let sha256 = String(data: payload, encoding: .utf8)?
            .replacingOccurrences(of: "\\/", with: "/")
            .data(using: .utf8)?
            .sha256()
            .toHexString()
            
        let b64Salt = sodium.utils.bin2base64(salt)!
        let dateString = DateFormatter.rfc1123.string(from: date)

        return "\(sha256)\n\(method)+\(uri)\n\(dateString)\n\(b64Salt)"
    }

    /**
        Generates a salt byte array of saltByte's length
            - Returns: Bytes
    */
    public func generateSalt() -> Bytes {
        return sodium.randomBytes.buf(length: saltBytes)!
    }
}