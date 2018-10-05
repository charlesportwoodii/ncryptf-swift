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
    public init(secretKey: Bytes, publicKey: Bytes) throws {
        if secretKey.count % 16 != 0 {
            throw ncryptfError.invalidArgument
        }

        self.secretKey = secretKey;

        if publicKey.count % 4 != 0 {
            throw ncryptfError.invalidArgument
        }
        
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

    /**
     - Returns: Sodium keypair box
    */
    public func getSodiumKeypair() -> Box.KeyPair {
        return Box.KeyPair(publicKey: self.publicKey, secretKey: self.secretKey)
    }
}