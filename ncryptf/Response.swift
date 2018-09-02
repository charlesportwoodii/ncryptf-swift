import Foundation
import Sodium

public struct Response {
    private var keypair: Box.KeyPair
    private let sodium = Sodium()
}

extension Response {
    public enum DecryptionError : Error {
        case decryptionFailed
    }

    /**
     Constructs a new response object
     - Parameters:
        - secretKey: Clients private key
        - publicKey: Server's public key
    */
    public init(secretKey: Bytes, publicKey: Bytes) {
        self.keypair = Box.KeyPair(publicKey: publicKey, secretKey: secretKey)
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
    public func decrypt(response: Bytes, nonce: Bytes) throws -> Data? {
        guard let decryptedResponse = sodium.box.open(
            authenticatedCipherText: response,
            senderPublicKey: keypair.publicKey,
            recipientSecretKey: keypair.secretKey,
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
}