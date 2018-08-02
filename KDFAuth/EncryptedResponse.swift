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
    public init(publicKey: Data, nonce: Data, hash: String, response: Data, signature: Data? = nil, signaturePublicKey: Data? = nil) {
        self.response = [UInt8](response)
        self.nonce = [UInt8](nonce)
        self.publicKey = [UInt8](publicKey)
        self.hash = hash

        if signature != nil && signaturePublicKey != nil {
            self.signature = [UInt8](signature!)
            self.signaturePublicKey = [UInt8](signaturePublicKey!)
        }
    }
}