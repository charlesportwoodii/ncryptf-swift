import Foundation
import Sodium
import CryptoSwift

public struct Authorization {
    private var hmac: Bytes?
    private var salt: Bytes
    private var date: Date
    private var signature: String

    private let sodium = Sodium()
}

extension Authorization {
    public enum Error : Swift.Error {
        case derivationError
    }

    /**
        Returns an authorization object
        - parameters:
            - method: The HTTP method
            - uri: The URI
            - tokens: The Token object containing the Initial Key Material, access and refresh tokens, and encryption strings
            - date: The current date. This should have an offset if the local time differs from the server time
            - payload: Raw payload data
            - version: The HMAC version to generate
        Throws: Key derivation error if the HMAC or HKDF cannot be calculated
    */
    public init(method: String, uri: String, tokens: Token, date: Date, payload: Data, version: Int? = 2) throws {
        self.date = date
        let sig = Signature()

        salt = sig.generateSalt()

        signature = sig.derive(
            method: method,
            uri: uri,
            salt: salt,
            date: date,
            payload: payload,
            version: version
        )

        do {
            let info: [UInt8] = Array("HMAC|AuthenticationKey".utf8)
            let kdf = try HKDF(password: tokens.ikm, salt: salt, info: info, variant: HMAC.Variant.sha256)
                .calculate()
            let signatureBytes: [UInt8] = Array(signature.utf8)
            hmac = try HMAC(key: kdf, variant: HMAC.Variant.sha256)
                .authenticate(signatureBytes)
        } catch {
            throw Error.derivationError
        }
    }

    /**
        Returns: signature string
    */
    public func getDateString() -> String? {
        return DateFormatter.rfc1123.string(from: date)
    }
    
    /**
        Returns: Base64 encoded HMAC
    */
    public func getEncodedHMAC() -> String? {
        return sodium.utils.bin2base64(hmac!)
    }

    /**
        Returns: Base64 encoded salt
    */
    public func getEncodedSalt() -> String? {
        return sodium.utils.bin2base64(salt)
    }

    /**
        Returns: Signature string
    */
    public func getSignatureString() -> String? {
        return signature
    }

    /**
        Returns the header string for the Authorization header
            - parameters:
                - token: The token containing the headers
                - verison: The version of the HMAC header to generate
        Returns: V2 header string
    */
    public func getHeaderString(token: Token, version: Int? = 2) -> String? {

        let salt = self.getEncodedSalt()!
        let hmac = self.getEncodedHMAC()!

        if version == 2 {
            let auth = "{ \"access_token\": \"\(token.accessToken)\", \"hmac\": \"\(hmac)\", \"salt\": \"\(salt)\" }".utf8
            return "HMAC \(sodium.utils.bin2base64([UInt8](auth)))"
        }

        return "HMAC \(token.accessToken),\(hmac),\(salt)"
    }
}