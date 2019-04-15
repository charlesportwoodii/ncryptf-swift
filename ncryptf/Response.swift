import Foundation
import Sodium

public struct Response {
    private var secretKey: Bytes
    private let sodium = Sodium()

    /**
     Constructs a new response object
     - Parameters:
        - secretKey: Clients private key
     - Throws: `ncryptf.invalidArgument`
               If the secret key length is invalid
    */
    public init(secretKey: Bytes) throws {
        if secretKey.count != self.sodium.box.SecretKeyBytes {
            throw ncryptfError.invalidArgument
        }

        self.secretKey = secretKey
    }
}

extension Response {
    /**
     Decrypts a response
     - Parameters:
        - response: Raw response to decrypt
     - Return: Decrypted data
    */
    public func decrypt(response: Bytes) throws -> Data? {
        if response.count < 236 {
            throw ncryptfError.invalidArgument
        }

        let nonce = Array(response[4..<28])
        let response = try self.decrypt(response: response, publicKey: nil, nonce: nonce)
        return response
    }

    /**
     Decrypts a versioned response
     - Parameters:
        - response: Raw response to decrypt
        - publicKey: 32 byte public key
        - nonce: 24 byte nonce
     - Return: Decrypted data
    */
    public func decrypt(response: Bytes, publicKey: Bytes?, nonce: Bytes) throws -> Data? {
        guard let version = try? Response.getVersion(response: response) else {
            throw ncryptfError.invalidArgument
        }

        if nonce.count != 24 {
            throw ncryptfError.invalidArgument
        }

        if version == 2 {
            if response.count < 236 {
                throw ncryptfError.invalidArgument
            }

            let payload = Array(response[0..<(response.count - 64)])
            let checksum = Array(response[(response.count - 64)..<response.count])

            let calculatedChecksum = self.sodium.genericHash.hash(message: payload, key: nonce, outputLength: 64)
            if !checksum.elementsEqual(calculatedChecksum!) {
                throw ncryptfError.invalidChecksum
            }

            let cPublicKey = Array(response[28..<60])
            let signature = Array(payload[(payload.count - 64)..<payload.count])
            let sigPubKey = Array(payload[(payload.count - 96)..<(payload.count - 64)])
            let body = Array(payload[60..<(payload.count - 96)])

            guard let decryptedPayload = try? self.decryptBody(response: body, publicKey: cPublicKey, nonce: nonce) else {
                throw ncryptfError.decryptionFailed
            }

            guard let isSignatureValid = try? self.isSignatureValid(response: decryptedPayload.bytes, signature: signature, publicKey: sigPubKey) else {
                throw ncryptfError.invalidSignature
            }

            if !isSignatureValid {
                throw ncryptfError.invalidSignature
            }

            return decryptedPayload
        }

        if publicKey == nil || publicKey!.count < self.sodium.box.PublicKeyBytes {
            throw ncryptfError.invalidArgument
        }

        guard let response = try? self.decryptBody(response: response, publicKey: publicKey!, nonce: nonce) else {
            throw ncryptfError.decryptionFailed
        }

        return response
    }

    /**
     Decrypts a response using the raw byte data and 24 byte nonce returned by the server
     - Parameters:
        - response: Raw response returned by the server
        - publicKey: 32 byte public key
        - nonce: 24 byte nonce returned by the server
     - Throws: `ncryptfError.decryptionFailed`
                If the response cannot be decrypted
     - Returns: Optional<Data> containing the decrypted data
    */
    private func decryptBody(response: Bytes, publicKey: Bytes, nonce: Bytes) throws -> Data? {
        if publicKey.count != self.sodium.box.PublicKeyBytes {
            throw ncryptfError.invalidArgument
        }

        if nonce.count != 24 {
            throw ncryptfError.invalidArgument
        }

        if response.count < self.sodium.box.MacBytes {
            throw ncryptfError.invalidArgument
        }

        guard let decryptedResponse = self.sodium.box.open(
            authenticatedCipherText: response,
            senderPublicKey: publicKey,
            recipientSecretKey: self.secretKey,
            nonce: nonce
        ) else {
            throw ncryptfError.decryptionFailed
        }

        return Data(bytes: decryptedResponse)
    }

    /**
     Returns true if the decrypted body matches the signature
     - Parameters:
        - response: Raw response returned by the server
        - signature: Signature byte array returned by the server
        - publicKey: The signature public key provided by the server
     - Returns: Will return true if the signature is valid, and false otherwise
    */
    public func isSignatureValid(response: Bytes, signature: Bytes, publicKey: Bytes) throws -> Bool {

        if signature.count != 64 {
            throw ncryptfError.invalidArgument
        }

        if publicKey.count != self.sodium.sign.PublicKeyBytes {
            throw ncryptfError.invalidArgument
        }

        return self.sodium.sign.verify(
            message: response,
            publicKey: publicKey,
            signature: signature
        )
    }

    /**
     Extracts the public key from the response
     - Parameters:
        - response: Raw response returned by server
     - Returns: 32 public key bytes
     - Throws: `ncryptfError.invalidArgument`
                If the response length is too short.
    */
    public static func getPublicKeyFromResponse(response: Bytes) throws -> Bytes? {
        guard let version = try? Response.getVersion(response: response) else {
            throw ncryptfError.invalidArgument
        }

        if version == 2 {
            if response.count < 236 {
                throw ncryptfError.invalidArgument
            }

            return Array(response[28..<60])
        }

        throw ncryptfError.invalidArgument
    }

    /**
     Extracts the signing public key from the response
     - Parameters:
        - response: Raw response returned by server
     - Returns: 32 public key bytes
     - Throws: `ncryptfError.invalidArgument`
                If the response length is too short.
    */
    public static func getSigningPublicKeyFromResponse(response: Bytes) throws -> Bytes? {
        guard let version = try? Response.getVersion(response: response) else {
            throw ncryptfError.invalidArgument
        }

        if version == 2 {
            if response.count < 236 {
                throw ncryptfError.invalidArgument
            }

            return Array(response[(response.count - 160)..<((response.count - 160) + 32)])
        }

        throw ncryptfError.invalidArgument
    }

    /**
     Returns the version number used in the payload
     - Parameters:
        - response: Raw response returned by server
     - Returns: Integer representation of the version being used by the payload
     - Throws: `ncryptfError.invalidArgument`
                If the response length is too short/
    */
    public static func getVersion(response: Bytes) throws -> Int {
        let sodium = Sodium()
        if response.count < sodium.box.MacBytes {
            throw ncryptfError.invalidArgument
        }

        let header = Array(response[0..<4])
        let hex = sodium.utils.bin2hex(header)!.uppercased()

        if (hex == "DE259002") {
            return 2
        }

        return 1
    }
}