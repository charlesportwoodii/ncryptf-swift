import Foundation
import Sodium

public struct EncryptedResponse {
    public var publicKey: Bytes
    public var nonce: Bytes
    public var hash: String
    public var signature: Bytes?
    public var signaturePublicKey: Bytes?
    public var response: Bytes

    private let sodium = Sodium()
}

extension EncryptedResponse {

    /**
        Creates a new encrypted response object to hold the encrypted response for parsing
        - parameters:
            - publicKey: The base64 public key string returned from the server
            - nonce: The base64 encoded nonce string returned from the server
            - response: The base64 encoded raw response returned from the server
            - hash: The X-Hashid provided by the server
            - signature: The base64 signature header returned by the server to verify the authenticity of the response
            - signaturePublicKey: The base64 encoded signature public key header returned by the server
    */
    public init(publicKey: String, nonce: String, hash: String, response: String, signature: String? = nil, signaturePublicKey: String? = nil) {
        self.response = sodium.utils.base642bin(response)!
        self.nonce = sodium.utils.base642bin(nonce)!
        self.publicKey = sodium.utils.base642bin(publicKey)!
        self.hash = hash

        if signature != nil && signaturePublicKey != nil {
            self.signature = sodium.utils.base642bin(signature!)!
            self.signaturePublicKey = sodium.utils.base642bin(signaturePublicKey!)!
        }
    }
}