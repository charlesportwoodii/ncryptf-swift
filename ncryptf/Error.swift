import Foundation

internal enum ncryptfError : Error {
    case decryptionFailed
    case encryptionFailed
    case invalidChecksum
    case invalidSignature
    case keyDerivation
    case signatureVerification
    case signingFailed
    case invalidArgument
}