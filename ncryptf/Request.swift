import Foundation
import Sodium

public struct Request {
    private var keypair: Box.KeyPair
    private var nonce: Bytes?

    private let sodium = Sodium()
}

extension Request {
    
    public enum EncryptionError : Error {
        case encryptionFailed
        case signingFailed
    }

    public init(secretKey: Bytes, publicKey: Bytes) {
        self.keypair = Box.KeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    public mutating func encrypt(request: Data, nonce: Bytes? = nil) throws -> Bytes? {
        if (nonce == nil) {
            self.nonce = sodium.box.nonce()
        } else {
            self.nonce = nonce
        }

        guard let encrypted = sodium.box.seal(
            message: request.bytes,
            recipientPublicKey: keypair.publicKey,
            senderSecretKey: keypair.secretKey,
            nonce: self.nonce!
        ) else {
            throw EncryptionError.encryptionFailed
        }

        return encrypted
    }

    public func sign(request: Data, secretKey: Bytes) throws -> Bytes? {
        
        guard let signature = sodium.sign.signature(
            message: request.bytes,
            secretKey: secretKey
        ) else {
            throw EncryptionError.signingFailed
        }

        return signature
    }

    public func getNonce() -> Bytes {
        return nonce!
    }
}