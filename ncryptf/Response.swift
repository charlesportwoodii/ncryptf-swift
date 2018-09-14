import Foundation
import Sodium

public struct Response {
    private var keypair: Keypair?
    private let secretKey: Bytes
    private let sodium = Sodium()
}

extension Response {
    public enum DecryptionError : Error {
        case decryptionFailed
        case invalidChecksum
        case invalidSignature
    }

    /**
     Constructs a new response object
     - Parameters:
        - secretKey: Clients private key
    */
    public init(secretKey: Bytes) {
        self.secretKey = secretKey
        self.keypair = nil
    }

    /**
     Constructs a new response object
     - Parameters:
        - secretKey: Clients private key
        - publicKey: Server's public key
    */
    public init(secretKey: Bytes, publicKey: Bytes) {
        self.secretKey = secretKey
        self.keypair = Keypair(secretKey: secretKey, publicKey: publicKey)
    }

    /**
     Decrypts a response
     - Parameters:
        - response: Raw response to decrypt
     - Return: Decrypted data
    */
    public mutating func decrypt(response: Bytes) throws -> Data? {
        let nonce = Array(response[4..<28])
        do {
            let response = try self.decrypt(response: response, nonce: nonce)
            return response
        } catch DecryptionError.invalidChecksum {
            throw DecryptionError.invalidChecksum
        } catch DecryptionError.invalidSignature {
            throw DecryptionError.invalidSignature
        } catch {
            throw DecryptionError.decryptionFailed
        }
    }

    /**
     Decrypts a versioned response
     - Parameters:
        - response: Raw response to decrypt
        - nonce: 24 byte nonce
     - Return: Decrypted data
    */
    public mutating func decrypt(response: Bytes, nonce: Bytes) throws -> Data? {
        let version = self.getVersion(response: response)
        if (version == 2) {
            let payload = Array(response[0..<(response.count - 64)])
            let checksum = Array(response[(response.count - 64)..<response.count])

            let calculatedChecksum = self.sodium.genericHash.hash(message: payload, key: nonce, outputLength: 64)
            if !checksum.elementsEqual(calculatedChecksum!) {
                throw DecryptionError.invalidChecksum
            }

            let publicKey = Array(response[28..<60])
            let signature = Array(payload[(payload.count - 64)..<payload.count])
            let sigPubKey = Array(payload[(payload.count - 96)..<(payload.count - 64)])
            let body = Array(payload[60..<(payload.count - 96)])

            self.keypair = Keypair(publicKey: publicKey, secretKey: self.secretKey)

            guard let decryptedPayload = try? self.decryptBody(response: body, nonce: nonce) else {
                throw DecryptionError.decryptionFailed
            }

            if !self.isSignatureValid(response: decryptedPayload!.bytes, signature: signature, publicKey: sigPubKey) {
                throw DecryptionError.invalidSignature
            }

            return decryptedPayload
        }

        guard let response = try? self.decryptBody(response: response, nonce: nonce) else {
            throw DecryptionError.decryptionFailed
        }

        return response
    }

    /**
     Decrypts a response using the raw byte data and 24 byte nonce returned by the server
     - Parameters:
        - response: Raw response returned by the server
        - nonce: 24 byte nonce returned by the server
     - Throws: `DecryptionError.decryptionFailed`
                If the response cannot be decrypted
     - Returns: Optional<Data> containing the decrypted data
    */
    private func decryptBody(response: Bytes, nonce: Bytes) throws -> Data? {
        guard let decryptedResponse = sodium.box.open(
            authenticatedCipherText: response,
            senderPublicKey: self.keypair!.getPublicKey(),
            recipientSecretKey: self.keypair!.getSecretKey(),
            nonce: nonce
        ) else {
            throw DecryptionError.decryptionFailed
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
    public func isSignatureValid(response: Bytes, signature: Bytes, publicKey: Bytes) -> Bool {
       return sodium.sign.verify(
            message: response,
            publicKey: publicKey,
            signature: signature
        )
    }

    /**
     Returns the version number used in the payload
     - Parameters:
        - response: Raw response returned by server
     - Returns: Integer representation of the version being used by the payload
    */
    private func getVersion(response: Bytes) -> Int {
        let header = Array(response[0..<4])
        let hex = self.sodium.utils.bin2hex(header)!.uppercased()

        if (hex == "DE259002") {
            return 2
        }

        return 1
    }
}