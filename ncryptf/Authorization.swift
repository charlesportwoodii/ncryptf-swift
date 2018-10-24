import Foundation
import Sodium
import CryptoSwift
import HKDF

public struct Authorization {
    private var token: Token
    private var salt: Bytes
    private var date: Date
    private var signature: String
    private var hmac: Bytes?
    private var version: Int? = 2

    private let sodium = Sodium()

    public let AUTH_INFO = "HMAC|AuthenticationKey"
    public let VARIANT = HMAC.Variant.sha256
}

extension Authorization {
    /**
     Returns an authorization object
     - Parameters:
        - httpMethod: The HTTP method
        - uri: The URI
        - token: The Token object containing the Initial Key Material, access and refresh tokens, and encryption strings
        - date: The current date. This should have an offset if the local time differs from the server time
        - payload: Raw payload data
        - version: The HMAC version to generate
     - Throws: Key derivation error if the HMAC or HKDF cannot be calculated
    */
    public init(httpMethod: String, uri: String, token: Token, date: Date, payload: Data, version: Int? = 2, salt: Bytes? = nil) throws {
        let method = httpMethod.uppercased()
        if (salt == nil) {
            self.salt = sodium.randomBytes.buf(length: Int(32))!
        } else {
            self.salt = salt!
        }
        self.date = date
        self.version = version
        self.token = token

        signature = Signature().derive(
            httpMethod: method,
            uri: uri,
            salt: self.salt,
            date: self.date,
            payload: payload,
            version: version
        )

        do {
            let hkdf = deriveKey(
                algorithm: .sha256,
                seed: Data(bytes: token.ikm, count: token.ikm.count),
                info: AUTH_INFO.data(using: .utf8),
                salt: Data(bytes: self.salt, count: self.salt.count),
                count: 32
            )

            let signatureBytes: [UInt8] = Array(signature.utf8)
            self.hmac = try HMAC(key: hkdf.toHexString(), variant: VARIANT)
                .authenticate(signatureBytes)
        } catch {
            throw ncryptfError.keyDerivation
        }
    }

    /**
     - Returns: Original `Date` object
    */
    public func getDate() -> Date {
        return date
    }

    /**
     -Returns: Formatted date string
    */
    public func getDateString() -> String? {
        return DateFormatter.rfc1123.string(from: date)
    }

    /**
     - Returns: 32 byte HMAC byte array
    */
    public func getHMAC() -> Bytes? {
        return hmac
    }

    /**
     - Returns: Base64 encoded HMAC
    */
    public func getEncodedHMAC() -> String? {
        return Data(bytes: hmac!, count: hmac!.count).base64EncodedString()
    }

    /**
     - Returns: Base64 encoded salt
    */
    public func getEncodedSalt() -> String? {
        return Data(bytes: salt, count: salt.count).base64EncodedString()
    }

    /**
     - Returns: The generated signature string
    */
    public func getSignatureString() -> String? {
        return signature
    }

    /**
     - Returns: The header authorization string
    */
    public func getHeader() -> String? {

        let salt = self.getEncodedSalt()!
        let hmac = self.getEncodedHMAC()!

        if self.version == 2 {
            let auth = "{\"access_token\":\"\(token.accessToken)\",\"date\":\"\(String(describing: self.getDateString()!))\",\"hmac\":\"\(hmac)\",\"salt\":\"\(salt)\",\"v\":2}"
                .replacingOccurrences(of: "/", with: "\\/")
                .data(using: .utf8, allowLossyConversion: false)!

            // sodium.utils.bin2base64() returns a malformed string
            let encodedAuth = Data(bytes: auth.bytes, count: auth.count).base64EncodedString()
            return "HMAC \(String(describing: encodedAuth))"
        }

        return "HMAC \(token.accessToken),\(hmac),\(salt)"
    }

    /**
     Validates a provided HMAC against an auth object and drift
     - Parameters:
        - hmac: 32 byte HMAC provided by the client
        - auth: Authorization object generated from the request
        - driftAllowance: Maximum amount of time in seconds that the request should be permitted to drift by
     - Returns: Boolean if the HMAC is valid
    */
    public func verify(hmac: Bytes, auth: Authorization, driftAllowance: Int = 90) -> Bool {
        let drift = self.getTimeDrift(date: auth.getDate())
        if (drift >= driftAllowance) {
            return false
        }

        if (self.sodium.utils.equals(hmac, auth.getHMAC()!)) {
            return true
        }

        return false
    }

    /**
     - Returns: Integer drift in seconds
    */
    private func getTimeDrift(date: Date) -> Int {
        let now = Date()

        return Int(abs(now.timeIntervalSince1970 - date.timeIntervalSince1970))
    }
}