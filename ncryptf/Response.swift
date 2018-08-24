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

    public init(secretKey: Bytes, publicKey: Bytes) {
        self.keypair = Box.KeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    public func decrypt(response: Data, nonce: Bytes) throws -> Data? {
        guard let decryptedResponse = sodium.box.open(
            authenticatedCipherText: response.bytes,
            senderPublicKey: keypair.publicKey,
            recipientSecretKey: keypair.secretKey,
            nonce: nonce
        ) else {
            throw DecryptionError.decryptionFailed
        }

        return Data(bytes: decryptedResponse)
    }

    public func isSignatureValid(response: Data, signature: Bytes, publicKey: Bytes) throws -> Bool {
       return sodium.sign.verify(
            message: response.bytes,
            publicKey: publicKey,
            signature: signature
        )
    }
}