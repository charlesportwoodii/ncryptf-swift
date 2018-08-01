import Foundation
import Sodium

public struct Token {
    public var accessToken: String
    public var refreshToken: String
    public var ikm: Bytes
    public var signature: Bytes
    public var expiresAt: Double
    private let sodium = Sodium()
}

extension Token {

    /**
        - parameters:
            - accessToken: The Access Token returned by the API
            - refreshToken: The Refresh Token returned by the API
            - ikm: The Initial Key Material returned by the API
            - signature: The signature date returned by the API
            - expiresAt: The expiration time returned by the API
    */
    public init (accessToken: String, refreshToken: String, ikm: String, signature: String, expiresAt: Double) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.ikm = sodium.utils.base642bin(ikm)!
        self.signature = sodium.utils.base642bin(signature)!
        self.expiresAt = expiresAt
    }

    /**
        Returns true if the current token is expires and requires refreshing
        - Returns: true or false
    */
    public func isExpired() -> Bool {
        let now = Date().timeIntervalSince1970;

        return now > expiresAt
    }
}