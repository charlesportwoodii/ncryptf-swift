import Foundation
import Sodium
import Clibsodium

public struct Request {
    private var secretKey: Bytes
    private var signatureSecretKey: Bytes
    private var nonce: Bytes?
    private let sodium = Sodium()

    /**
     Constructs a new request object
     - Parameters:
        - secretKey: Clients private key
        - signatureSecretKey: Server's public key
     - Throws: `ncryptfError.invalidArgument`
        If the inputs don't match the expected length
    */
    public init(secretKey: Bytes, signatureSecretKey: Bytes) throws {
        if secretKey.count != self.sodium.box.SecretKeyBytes {
            throw ncryptfError.invalidArgument
        }

        self.secretKey = secretKey

        if signatureSecretKey.count != self.sodium.sign.SecretKeyBytes {
            throw ncryptfError.invalidArgument
        }
        
        self.signatureSecretKey = signatureSecretKey
    }
}

extension Request {
    /**
     Encrypts a plain text response
     - Parameters:
        - request: Data representation of the data to encrypt (plain text)
        - remotePublicKey: 32 byte public key.
        - version: Version to use
        - nonce: Optional 24 byte nonce.
                 If a nonce is not provided, one will be generated
     - Throws: `ncryptfError.encryptionFailed`
               If the request cannot be encrypted, an error will be thrown
               `ncryptfError.invalidArgument`
               If the remotePublicKey byte length does not meet the minimum length
     - Returns: Byte array containing the encrypted data
    */
    public mutating func encrypt(request: Data, publicKey: Bytes, version: Int? = 2, nonce: Bytes? = nil) throws -> Bytes? {
        self.nonce = nonce ?? self.sodium.box.nonce()

        if publicKey.count != self.sodium.box.PublicKeyBytes {
            throw ncryptfError.invalidArgument
        }

        if version == 2 {
            do {
                let header = self.sodium.utils.hex2bin("DE259002")
                let body = try self.encryptBody(request: request, publicKey: publicKey, nonce: self.nonce!)

                var publicKey = Array<UInt8>(repeating: 0, count: 32)
                if crypto_scalarmult_base(&publicKey, self.secretKey) != 0 {
                    throw ncryptfError.encryptionFailed
                }

                var sigPubKey = Array<UInt8>(repeating: 0, count: 32)
                if crypto_sign_ed25519_sk_to_pk(&sigPubKey, self.signatureSecretKey) != 0 {
                    throw ncryptfError.encryptionFailed
                }

                let signature = try self.sign(request: request)

                let payload = header! + 
                    self.nonce! +
                    publicKey +
                    body! +
                    sigPubKey +
                    signature!
                
                let checksum = self.sodium.genericHash.hash(message: payload, key: self.nonce!, outputLength: 64)

                return payload + checksum!
            } catch {
                throw ncryptfError.encryptionFailed
            }

        }

        if let encrypted = try? self.encryptBody(request: request, publicKey: publicKey, nonce: self.nonce!) {
            return encrypted
        } else {
            throw ncryptfError.encryptionFailed
        }
    }

    /**
     Encrypts a plain text response
     - Parameters:
        - request: Data representation of the data to encrypt (plain text)
        - publicKey: 32 byte public key
        - nonce: 24 byte nonce.
     - Throws: `EncryuptionError.encryptionFailed`
               If the request cannot be encrypted, an error will be thrown
     - Returns: Byte array containing the encrypted data
    */
    private func encryptBody(request: Data, publicKey: Bytes, nonce: Bytes) throws -> Bytes? {
        guard let encrypted = self.sodium.box.seal(
            message: request.bytes,
            recipientPublicKey: publicKey,
            senderSecretKey: self.secretKey,
            nonce: nonce
        ) else {
            throw ncryptfError.encryptionFailed
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
    public func sign(request: Data) throws -> Bytes? {
        guard let signature = self.sodium.sign.signature(
            message: request.bytes,
            secretKey: self.signatureSecretKey
        ) else {
            throw ncryptfError.signingFailed
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