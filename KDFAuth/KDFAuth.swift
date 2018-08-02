import Foundation
import Sodium

public struct KDFAuth {
}

extension KDFAuth {
    
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
    static public func getAuthorizationData(method: String, uri: String, tokens: Token, date: Date, payload: Data) throws -> Authorization {
        return try Authorization(
            method: method,
            uri: uri,
            tokens: tokens,
            date: date,
            payload: payload
        )
    }

    /**
        Returns a new token object to store credentials provided by the API
        - parameters:
            - accessToken: The Access Token returned by the API
            - refreshToken: The Refresh Token returned by the API
            - ikm: The Initial Key Material returned by the API
            - signature: The signature date returned by the API
            - expiresAt: The expiration time returned by the API
    */
    static public func createToken(accessToken: String, refreshToken: String, ikm: Data, signature: Data, expiresAt: Double) -> Token {
        return Token(
            accessToken: accessToken,
            refreshToken: refreshToken,
            ikm: ikm,
            signature: signature,
            expiresAt: expiresAt
        )
    }

    /**
        Creates a new session
        - paramters:
            - key: The public key provided by the server OTK endpoint
        
        Returns: Session object
    */
    static public func createSession(key: Data) -> Session {
        return Session(serverKey: key)
    }

    /**
        Creates a new encrypted response object to hold the encrypted response for parsing
        - parameters:
            - publicKey: The base64 public key string returned from the server
            - nonce: The base64 encoded nonce string returned from the server
            - hash: The X-Hashid header returned by the server
            - response: The base64 encoded raw response returned from the server
            - signature: The base64 signature header returned by the server to verify the authenticity of the response
            - signaturePublicKey: The base64 encoded signature public key header returned by the server

        Returns: EncryptedResponse object used to represent the response
    */
    static public func createEncryptedResponse(publicKey: Data, nonce: Data, hash: String, response: Data, signature: Data? = nil, signaturePublicKey: Data? = nil) -> EncryptedResponse {
        return EncryptedResponse(
            publicKey: publicKey,
            nonce: nonce,
            hash: hash,
            response: response,
            signature: signature,
            signaturePublicKey: signaturePublicKey
        )
    }
}