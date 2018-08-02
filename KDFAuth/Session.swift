import Foundation
import Sodium

public struct Session {
    private var serverKey: Bytes
    private var myKey: Box.KeyPair

    private let sodium = Sodium()
}

extension Session {
    public enum SignatureVerificationError : Swift.Error {
        case invalidSignature
    }

    public enum EncryptionError : Swift.Error {
        case decryptionFailed
        case encryptionFailed
    }

    public init (serverKey: Data) {
        myKey = sodium.box.keyPair()!
        self.serverKey = sodium.utils.base642bin(String(data: serverKey, encoding: .utf8)!)!
    }

    /**
        Sets the server key when it changes
        - parameters:
            severKey: The byte interpretation of the server key
    */
    internal mutating func setServerKey(serverKey: Bytes) {
        self.serverKey = serverKey
    }

    /**
        Returns: The secret key bytes
    */
    internal func getPrivateKey() -> Bytes {
        return myKey.secretKey
    }

    /**
        Returns: Binary public key for the client
    */
    public func getPublicKey() -> Bytes {
        return myKey.publicKey
    }

    /**
        Returns: Base64 encoded public key for the client
    */
    public func getEncodedPublicKey() -> String {
        return sodium.utils.bin2base64(myKey.publicKey)!
    }

    /**
        Creates an encrypted request body
        - parameters:
            - payload: The payload data
        Throws: EncryptionError.encryptionFailed
        Returns: Base64 encoded payload
    */
    public func encryptRequest(payload: Data) throws -> String {
        let nonce = sodium.box.nonce()
        let message = payload.bytes

        guard let encrypted = sodium.box.seal(
            message: message,
            recipientPublicKey: serverKey,
            senderSecretKey: myKey.secretKey,
            nonce: nonce
        ) else {
            throw EncryptionError.encryptionFailed
        }

        return sodium.utils.bin2base64(encrypted)!
    }

    /**
        Decrypts an API response and optionally checks the signature
        - parameters:
            - response: EncryptedResponse
        Throws: SignatureVerificationError.invalidSignature
        Returns: Decrypted response as a string. Data can be transformed from a string to an appropriate format
    */
    public mutating func decryptResponse(response: EncryptedResponse) throws -> String? {
        self.setServerKey(serverKey: response.publicKey)

        guard let decryptedResponse = sodium.box.open(
            authenticatedCipherText: response.response,
            senderPublicKey: self.getPublicKey(),
            recipientSecretKey: self.getPrivateKey(),
            nonce: response.nonce
        ) else {
            throw EncryptionError.decryptionFailed
        }

        let rawResponse = String(bytes: decryptedResponse, encoding: String.Encoding.utf8)

        // If the signature and signature public key was provided
        // we should verify it before sending the response
        if response.signature != nil && response.signaturePublicKey != nil {
            if sodium.sign.verify(
                message: response.response,
                publicKey: response.signaturePublicKey!, 
                signature: response.signature!
            ) {
                return rawResponse
            } else {
                throw SignatureVerificationError.invalidSignature
            }
        }

        return rawResponse
    }
}