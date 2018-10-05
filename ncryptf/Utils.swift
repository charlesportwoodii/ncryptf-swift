import Foundation
import Sodium
import CryptoSwift

public class Utils {
    private static let sodium = Sodium()

    /**
     Securely zeros memory block
     - Parameters:
        - data: Data object to zero
     - Returns: true if each byte was zeroed
    */
    public static func zero(_ data: inout Bytes) -> Bool {
        self.sodium.utils.zero(&data)
        for i in 0..<data.count {
            if data[i] != 0 {
                return false
            }
        }

        return true
    }

    /**
     - Returns: Crypto box Keypair
    */
    public static func generateKeypair() throws -> Keypair {
        let kp = self.sodium.box.keyPair()!
        return try Keypair(secretKey: kp.secretKey, publicKey: kp.publicKey)
    }

    /**
     - Returns: Crypto sign Keypair
    */
    public static func generateSigningKeypair() throws -> Keypair {
        let kp = self.sodium.sign.keyPair()!
        return try Keypair(secretKey: kp.secretKey, publicKey: kp.publicKey)
    }
}