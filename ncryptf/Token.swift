import Foundation
import Sodium
import Clibsodium

public struct Token {
    public let accessToken: String
    public let refreshToken: String
    public let ikm: Bytes
    public let signature: Bytes
    public let expiresAt: Double
}

extension Token {

    /**
     Generates a new object to represent a server token set
     - Parameters:
        - accessToken: The Access Token returned by the API
        - refreshToken: The Refresh Token returned by the API
        - ikm: The Initial Key Material returned by the API
        - signature: The signature date returned by the API
        - expiresAt: The expiration time returned by the API
    */
    public init (accessToken: String, refreshToken: String, ikm: Data, signature: Data, expiresAt: Double) throws {
        self.accessToken = accessToken
        self.refreshToken = refreshToken

        if ikm.count != 32  {
            throw ncryptfError.invalidArgument
        }

        self.ikm = [UInt8](ikm)

        if signature.count != 64 {
            throw ncryptfError.invalidArgument
        }

        self.signature = [UInt8](signature)
        self.expiresAt = expiresAt
    }

    /**
     - Returns: `true` if the current token is expires and requires refreshing
    */
    public func isExpired() -> Bool {
        let now = Date().timeIntervalSince1970;
        return now > expiresAt
    }

    /**
     Extracts the signature public key from the secret key
     - Returns: Bytes?
    */
    public func getSignaturePublicKey() -> Bytes? {
        var sigPubKey = Array<UInt8>(repeating: 0, count: 32)
        if crypto_sign_ed25519_sk_to_pk(&sigPubKey, self.signature) != 0 {
            return nil
        }

        return sigPubKey
    }
}
