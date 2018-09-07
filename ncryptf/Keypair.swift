import Foundation
import Sodium
import CryptoSwift

public struct Keypair {
    public var publicKey: Bytes
    public var secretKey: Bytes
    private let sodium = Sodium()
}

extension Keypair {

    /**
     Constructor
     - Parameters:
        - secretKey: Secret key bytes
        - publicKey: Public key bytes
    */
    public init(secretKey: Bytes, publicKey: Bytes) {
        self.secretKey = secretKey;
        self.publicKey = publicKey;
    }

    /**
     - Returns: Public key bytes
    */
    public func getPublicKey() -> Bytes {
        return self.publicKey
    }

    /**
     - Returns: Secret key bytes
    */
    public func getSecretKey() -> Bytes {
        return self.secretKey
    }
}