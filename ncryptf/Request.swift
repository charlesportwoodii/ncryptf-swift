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

    /**
     Constructs a new request object
     - Parameters:
        - secretKey: Clients private key
        - publicKey: Server's public key
    */
    public init(secretKey: Bytes, publicKey: Bytes) {
        self.keypair = Box.KeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    /**
     Encrypts a plain text response
     - Parameters:
        - request: Data representation of the data to encrypt (plain text)
        - nonce: Optional 24 byte nonce.
                 If a nonce is not provided, one will be generated
     - Throws: `EncryuptionError.encryptionFailed`
               If the request cannot be encrypted, an error will be thrown
     - Returns: Byte array containing the encrypted data
    */
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

    /**
     Signs the request using the raw data and a private signing key
     - Parameters:
        - request: Data representation of the data to sign (plain text)
        - secretKey: 32 byte secret key used to sign the request
     - Throws: `EncryptionError.signingFailed`
               An error will be thrown if signing is unable to succeed
     - Returns: Byte array of the signature
    */
    public func sign(request: Data, secretKey: Bytes) throws -> Bytes? {
        guard let signature = sodium.sign.signature(
            message: request.bytes,
            secretKey: secretKey
        ) else {
            throw EncryptionError.signingFailed
        }

        return signature
    }

    /**
     - Returns: The nonce used to encrypt the request
    */
    public func getNonce() -> Bytes {
        return nonce!
    }
}