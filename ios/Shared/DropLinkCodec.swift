import CryptoKit
import Foundation

enum DropLinkError: Error, LocalizedError {
  case invalidBase64URL
  case malformed
  case unsupportedVersion(Int)
  case badSignature

  var errorDescription: String? {
    switch self {
    case .invalidBase64URL: return "The link is not valid base64url."
    case .malformed: return "The Drop link is malformed."
    case .unsupportedVersion(let version): return "Unsupported Drop link version \(version)."
    case .badSignature: return "The Drop link signature is invalid."
    }
  }
}

struct DropLinkPayload: Hashable {
  static let version = 2
  static let signatureLength = 64

  var keyId: Int
  var linkId: Data
  var shareKey: String
  var label: String
  var sealedEmail: Data
  var serverSignature: Data
}

enum DropLinkCodec {
  static func decode(fragment: String) throws -> DropLinkPayload {
    try decode(bytes: Base64URL.decode(fragment))
  }

  static func decode(bytes: Data) throws -> DropLinkPayload {
    guard bytes.count > DropLinkPayload.signatureLength else { throw DropLinkError.malformed }
    var offset = 0
    func take(_ count: Int) throws -> Data {
      guard offset + count <= bytes.count else { throw DropLinkError.malformed }
      defer { offset += count }
      return bytes.subdata(in: offset..<(offset + count))
    }

    let version = Int(try take(1)[0])
    guard version == DropLinkPayload.version else { throw DropLinkError.unsupportedVersion(version) }
    let keyId = Int(try take(1)[0])
    let linkId = try take(8)
    let shareLength = Int(try take(1)[0])
    guard shareLength > 0 else { throw DropLinkError.malformed }
    let shareBytes = try take(shareLength)
    guard let shareKey = String(data: shareBytes, encoding: .utf8) else { throw DropLinkError.malformed }
    let labelLength = Int(try take(1)[0])
    let labelBytes = try take(labelLength)
    guard let label = String(data: labelBytes, encoding: .utf8) else { throw DropLinkError.malformed }
    let sealedLenBytes = try take(2)
    let sealedLength = (Int(sealedLenBytes[0]) << 8) | Int(sealedLenBytes[1])
    guard sealedLength > 0 else { throw DropLinkError.malformed }
    let sealedEmail = try take(sealedLength)
    let signature = try take(DropLinkPayload.signatureLength)
    guard offset == bytes.count else { throw DropLinkError.malformed }
    return DropLinkPayload(keyId: keyId, linkId: linkId, shareKey: shareKey, label: label, sealedEmail: sealedEmail, serverSignature: signature)
  }

  static func verify(fragment: String, publicJWK: [String: String]) throws -> DropLinkPayload {
    let bytes = try Base64URL.decode(fragment)
    let payload = try decode(bytes: bytes)
    let signed = bytes.prefix(bytes.count - DropLinkPayload.signatureLength)
    guard let x = publicJWK["x"], let y = publicJWK["y"] else { throw DropLinkError.malformed }
    var keyBytes = Data([0x04])
    keyBytes.append(try Base64URL.decode(x))
    keyBytes.append(try Base64URL.decode(y))
    let key = try P256.Signing.PublicKey(x963Representation: keyBytes)
    let sig = try P256.Signing.ECDSASignature(rawRepresentation: payload.serverSignature)
    guard key.isValidSignature(sig, for: SHA256.hash(data: signed)) else { throw DropLinkError.badSignature }
    return payload
  }
}
