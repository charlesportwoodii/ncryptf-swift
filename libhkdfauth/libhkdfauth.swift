import Foundation
import Sodium

public struct libhkdfauth {
    
}

extension libhkdfauth {

    /**
        Returns an authorization object
        - parameters:
            - method: The HTTP method
            - uri: The URI
            - tokens: The Token object containing the Initial Key Material, access and refresh tokens, and encryption strings
            - date: The current date. This should have an offset if the local time differs from the server time
            - payload: Raw payload data
        - Throws: Key derivation error if the HMAC or HKDF cannot be calculated
        - Returns: Authorization
    */
    public func getAuthorizationData(method: String, uri: String, tokens: Token, date: Date, payload: Data) throws -> Authorization {
        return try Authorization(method: method, uri: uri, tokens: tokens, date: date, payload: payload)
    }

    /**
        - parameters:
            - accessToken: The Access Token returned by the API
            - refreshToken: The Refresh Token returned by the API
            - ikm: The Initial Key Material returned by the API
            - signature: The signature date returned by the API
            - expiresAt: The expiration time returned by the API
    */
    public func createToken(accessToken: String, refreshToken: String, ikm: String, signature: String, expiresAt: Double) -> Token {
        return Token(accessToken: accessToken, refreshToken: refreshToken, ikm: ikm, signature: signature, expiresAt: expiresAt)
    }
}