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

    public init (serverKey: String) {
        myKey = sodium.box.keyPair()!
        self.serverKey = sodium.utils.base642bin(serverKey)!
    }

    private mutating func setServerKey(serverKey: Bytes) {
        self.serverKey = serverKey
    }
    
    private mutating func setServerKey(serverKey: String) {
        self.serverKey = sodium.utils.base642bin(serverKey)!
    }

    private func getPrivateKey() -> Bytes {
        return myKey.secretKey
    }

    public func getPublicKey() -> Bytes {
        return myKey.publicKey
    }

    public func getEncodedPublicKey() -> String {
        return sodium.utils.bin2base64(myKey.publicKey)!
    }

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