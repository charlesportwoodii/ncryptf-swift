import Foundation
import Alamofire
import Sodium
import CryptoSwift

extension URLRequest {
    mutating func addHmacSignature(method: HTTPMethod, uri: String, payload: Data?, ikm: Bytes, accessToken: String, date: Date? = nil) {
        let signature = Signature()

        guard let salt = signature.generateSalt() else {
            return
        }

        guard let signatureString = signature.derive(
            method: method.rawValue,
            uri: uri,
            salt: salt,
            date: date,
            payload: payload
        ) else {
            return
        }

        do {
            let info: [UInt8] = Array("HMAC|AuthenticationKey".utf8)
            let hkdf = try HKDF(password: ikm, salt: salt, info: info, variant: .sha256)
            do {
                let signatureBytes: [UInt8] = Array(signatureString.utf8)
                let hmac = try HMAC(key: hkdf, variant: .sha256)
                    .authenticate(signatureBytes)

                let sodium = Sodium()
                let b64Hmac = sodium.utils.bin2base64(hmac)!
                let b64Salt = sodium.utils.bin2base64(salt)!

                let dateString = DateFormatter.rfc1123.string(from: date!)
                addValue("HMAC " + accessToken + "," + b64Hmac + "," + b64Salt, forHTTPHeaderField: "Authorization")
                addValue(dateString, forHTTPHeaderField: "X-Date")
            } catch {
                return
            }
        } catch {
            return
        }
    }
}