import Foundation
import Sodium
import CryptoSwift

public struct Signature {
    private let sodium = Sodium()
}

extension Signature {

    /**
     Derives a signature for hashing
     - Parameters:
        - httpMethod: The HTTP method
        - uri: The URI of the request
        - bytes: The salt bytes
        - date: The date
        - data: The encoded data
     - Returns: The signature string
    */
    public func derive(httpMethod: String, uri: String, salt: Bytes, date: Date, payload: Data, version: Int? = 2) -> String {
        
        let method = httpMethod.uppercased()
        
        let hash = getSignatureHash(
            data: payload,
            salt: salt,
            version: version
        )!

        let time = DateFormatter.rfc1123.string(from: date)
        // sodium.utils.bin2base64() returns a malformed string
        let b64Salt = Data(bytes: salt, count: salt.count).base64EncodedString()

        return "\(String(describing: hash))\n\(method)+\(uri)\n\(time)\n\(b64Salt)"
    }

    /**
     Generates a signature hash
     - Parameters:
        - data: The data to hash
        - salt: 32 byte salt
        - version: The signature hash version to generate. Defaults to version 2
     - Returns: A string representing the signature hash
    */
    private func getSignatureHash(data: Data, salt: Bytes, version: Int? = 2) -> String? {
        let hash: String?
        if version == 2 {
            let genericHash = sodium.genericHash.hash(message: data.bytes, key: salt, outputLength: 64)!
            // sodium.utils.bin2base64() returns a malformed string
            hash = Data(bytes: genericHash, count: genericHash.count).base64EncodedString()
        } else {
            hash = String(data: data, encoding: .utf8)?
                .replacingOccurrences(of: "\\/", with: "/")
                .data(using: .utf8)?
                .sha256()
                .toHexString()
        }

        return hash
    }
}