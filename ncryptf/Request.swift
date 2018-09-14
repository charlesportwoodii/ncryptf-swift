import Foundation
import Sodium
import Clibsodium

public struct Request {
    private var keypair: Keypair
    private var nonce: Bytes?

    private let sodium = Sodium()
}

extension Request {
    public enum EncryptionError : Error {
        case encryptionFailed
        case signingFailed
        case invalidArgument
    }

    /**
     Constructs a new request object
     - Parameters:
        - secretKey: Clients private key
        - publicKey: Server's public key
    */
    public init(secretKey: Bytes, publicKey: Bytes) {
        self.keypair = Keypair(publicKey: publicKey, secretKey: secretKey)
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
        guard let encrypted = try? self.encrypt(request: request, signatureKey: nil, version: 1, nonce: nonce) else {
            throw EncryptionError.encryptionFailed
        }

        return encrypted
    }

    /**
     Encrypts a plain text response
     - Parameters:
        - request: Data representation of the data to encrypt (plain text)
        - signatureKey: 32 byte signature key. Optional for v1, required for v2
     - Throws: `EncryuptionError.encryptionFailed`
               If the request cannot be encrypted, an error will be thrown
     - Returns: Byte array containing the encrypted data
    */
    public mutating func encrypt(request: Data, signatureKey: Bytes? = nil) throws -> Bytes? {
        guard let encrypted = try? self.encrypt(request: request, signatureKey: signatureKey, version: 2, nonce: nil) else {
            throw EncryptionError.encryptionFailed
        }

        return encrypted
    }

    /**
     Encrypts a plain text response
     - Parameters:
        - request: Data representation of the data to encrypt (plain text)
        - signatureKey: 32 byte signature key. Optional for v1, required for v2
        - nonce: Optional 24 byte nonce.
                 If a nonce is not provided, one will be generated
     - Throws: `EncryuptionError.encryptionFailed`
               If the request cannot be encrypted, an error will be thrown
     - Returns: Byte array containing the encrypted data
    */
    public mutating func encrypt(request: Data, signatureKey: Bytes? = nil, nonce: Bytes? = nil) throws -> Bytes? {
        guard let encrypted = try? self.encrypt(request: request, signatureKey: signatureKey, version: 2, nonce: nonce) else {
            throw EncryptionError.encryptionFailed
        }

        return encrypted
    }

    /**
     Encrypts a plain text response
     - Parameters:
        - request: Data representation of the data to encrypt (plain text)
        - signatureKey: 32 byte signature key. Optional for v1, required for v2
        - version: Version to use
        - nonce: Optional 24 byte nonce.
                 If a nonce is not provided, one will be generated
     - Throws: `EncryuptionError.encryptionFailed`
               If the request cannot be encrypted, an error will be thrown
     - Returns: Byte array containing the encrypted data
    */
    public mutating func encrypt(request: Data, signatureKey: Bytes? = nil, version: Int? = 2, nonce: Bytes? = nil) throws -> Bytes? {
        self.nonce = nonce ?? sodium.box.nonce()

        if version == 2 {
            if (signatureKey == nil || signatureKey!.count != 64) {
                throw EncryptionError.invalidArgument
            }

            do {
                let header = sodium.utils.hex2bin("DE259002")
                let body = try self.encryptBody(request: request, nonce: self.nonce)

                var publicKey = Array<UInt8>(repeating: 0, count: 32)
                if crypto_scalarmult_base(&publicKey, self.keypair.getSecretKey()) != 0 {
                    throw EncryptionError.encryptionFailed
                }

                var sigPubKey = Array<UInt8>(repeating: 0, count: 32)
                if crypto_sign_ed25519_sk_to_pk(&sigPubKey, signatureKey!) != 0 {
                    throw EncryptionError.encryptionFailed
                }

                let signature = try self.sign(request: request, secretKey: signatureKey!)

                let payload = header! + 
                    self.nonce! +
                    publicKey +
                    body! +
                    sigPubKey +
                    signature!
                
                let checksum = self.sodium.genericHash.hash(message: payload, key: self.nonce, outputLength: 64)

                return payload + checksum!
            } catch {
                throw EncryptionError.encryptionFailed
            }

        }

        if let encrypted = try? self.encryptBody(request: request, nonce: self.nonce) {
            return encrypted
        } else {
            throw EncryptionError.encryptionFailed
        }
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
    private func encryptBody(request: Data, nonce: Bytes?) throws -> Bytes? {
        guard let encrypted = sodium.box.seal(
            message: request.bytes,
            recipientPublicKey: self.keypair.getPublicKey(),
            senderSecretKey: self.keypair.getSecretKey(),
            nonce: nonce!
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