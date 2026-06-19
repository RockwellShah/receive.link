import CryptoKit
import Foundation
import Security
import UniformTypeIdentifiers

enum FileKeyCryptoError: Error, LocalizedError {
  case invalidShareKey
  case invalidFile
  case authenticationFailed

  var errorDescription: String? {
    switch self {
    case .invalidShareKey: return "The FileKey share key is invalid."
    case .invalidFile: return "The file is not a valid FileKey ciphertext."
    case .authenticationFailed: return "The file could not be authenticated or decrypted."
    }
  }
}

struct FileKeyMetadata: Equatable {
  var filename: String
  var mimeType: String
  var originalSize: Int
  var createdAtUnixMs: Int
}

struct FileKeyIdentity {
  var privateKey: P256.KeyAgreement.PrivateKey

  var publicKeyBytes: Data {
    privateKey.publicKey.x963Representation
  }
}

struct FileKeyCrypto {
  private enum C {
    static let magic = Data([0x46, 0x4b, 0x45, 0x59])
    static let formatVersion: UInt8 = 0x01
    static let suiteId: UInt8 = 0x01
    static let shareKeyVersion: UInt8 = 0x01
    static let headerLength = 12
    static let publicKeyLength = 65
    static let encLength = 65
    static let chunkSize = 65_536
    static let gcmTagLength = 16
    static let metadataNonce = Data(repeating: 0, count: 12)
    static let labelHPKEInfo = "FILEKEY-v1/hpke-info"
    static let labelPayloadKey = "FILEKEY-v1 payload-key"
    static let labelMetadataKey = "FILEKEY-v1 metadata-key"
    static let labelPRFInput = "FILEKEY-v1/prf-input/identity"
    static let labelMasterPRK = "FILEKEY-v1/master-prk"
    static let labelIdentityKEM = "FILEKEY-v1/identity-kem"
    static let hpkeVersionLabel = "HPKE-v1"
    static let kemSuiteId = Data([0x4b, 0x45, 0x4d, 0x00, 0x10])
    static let rpId = "filekey.app"
  }

  func shareKey(identity: FileKeyIdentity) -> String {
    Self.encodeShareKey(publicBytes: identity.publicKeyBytes)
  }

  static func prfInputSalt() -> Data {
    Data(SHA256.hash(data: Data(C.labelPRFInput.utf8)))
  }

  static func identity(fromPRFSecret prfSecret: Data) throws -> FileKeyIdentity {
    guard prfSecret.count == 32 else { throw FileKeyCryptoError.authenticationFailed }
    let masterPRK = hkdfExtract(inputKeyMaterial: prfSecret, salt: Data(C.labelMasterPRK.utf8))
    let identityIKM = hkdfExpand(
      pseudoRandomKey: masterPRK,
      info: Data(C.labelIdentityKEM.utf8) + Data(C.rpId.utf8),
      outputByteCount: 32
    )
    return try FileKeyIdentity(privateKey: deriveP256PrivateKey(ikm: identityIKM))
  }

  static func throwawayIdentity() throws -> FileKeyIdentity {
    try identity(fromPRFSecret: randomData(count: 32))
  }

  func encryptForUpload(fileURL: URL, recipientShareKey: String) throws -> Data {
    let plaintext = try Data(contentsOf: fileURL)
    let values = try? fileURL.resourceValues(forKeys: [.contentTypeKey, .creationDateKey])
    let metadata = FileKeyMetadata(
      filename: fileURL.lastPathComponent,
      mimeType: values?.contentType?.preferredMIMEType ?? "application/octet-stream",
      originalSize: plaintext.count,
      createdAtUnixMs: values?.creationDate.map { Int($0.timeIntervalSince1970 * 1000) } ?? 0
    )
    return try encrypt(plaintext: plaintext, metadata: metadata, recipientShareKey: recipientShareKey, senderIdentity: Self.throwawayIdentity())
  }

  func encrypt(plaintext: Data, metadata: FileKeyMetadata, recipientShareKey: String, senderIdentity: FileKeyIdentity) throws -> Data {
    let sealedMetadata = FileKeyMetadata(
      filename: metadata.filename,
      mimeType: metadata.mimeType,
      originalSize: plaintext.count,
      createdAtUnixMs: metadata.createdAtUnixMs
    )
    let senderPrivate = senderIdentity.privateKey
    let senderPublic = senderPrivate.publicKey.x963Representation
    let recipientPublic = try Self.decodeShareKey(recipientShareKey)
    let header = Self.buildHeader()
    let info = Self.buildInfo(header: header, senderPublic: senderPublic, recipientPublic: recipientPublic)
    let recipientKey = try P256.KeyAgreement.PublicKey(x963Representation: recipientPublic)
    let sender = try HPKE.Sender(
      recipientKey: recipientKey,
      ciphersuite: .P256_SHA256_AES_GCM_256,
      info: info,
      authenticatedBy: senderPrivate
    )
    let enc = sender.encapsulatedKey
    let aad = header + senderPublic + enc
    let metadataKey = try sender.exportSymmetricKey(context: C.labelMetadataKey)
    let payloadKey = try sender.exportSymmetricKey(context: C.labelPayloadKey)
    let metadataCiphertext = try Self.aesSeal(key: metadataKey, nonce: C.metadataNonce, aad: aad, plaintext: Self.encodeMetadata(sealedMetadata))

    var output = Data()
    output.append(aad)
    output.append(Self.u32(metadataCiphertext.count))
    output.append(metadataCiphertext)

    let totalChunks = plaintext.isEmpty ? 1 : Int(ceil(Double(plaintext.count) / Double(C.chunkSize)))
    for index in 0..<totalChunks {
      let start = index * C.chunkSize
      let end = min(start + C.chunkSize, plaintext.count)
      let chunk = plaintext.subdata(in: start..<end)
      output.append(try Self.aesSeal(key: payloadKey, nonce: Self.chunkNonce(index: index, isLast: index == totalChunks - 1), aad: aad, plaintext: chunk))
    }
    return output
  }

  func decryptDownloadedFile(_ data: Data, recipientIdentity: FileKeyIdentity) throws -> Data {
    try decrypt(data, recipientIdentity: recipientIdentity).plaintext
  }

  func decrypt(_ data: Data, recipientIdentity: FileKeyIdentity) throws -> (metadata: FileKeyMetadata, plaintext: Data) {
    guard data.count >= C.headerLength + C.publicKeyLength + C.encLength + 4 else { throw FileKeyCryptoError.invalidFile }
    let header = data.subdata(in: 0..<C.headerLength)
    try Self.validateHeader(header)
    let senderPublic = data.subdata(in: C.headerLength..<(C.headerLength + C.publicKeyLength))
    let encStart = C.headerLength + C.publicKeyLength
    let enc = data.subdata(in: encStart..<(encStart + C.encLength))
    let metaLenStart = encStart + C.encLength
    let metaLen = Self.readU32(data, offset: metaLenStart)
    let metaStart = metaLenStart + 4
    guard metaLen >= 17, data.count >= metaStart + metaLen + C.gcmTagLength else { throw FileKeyCryptoError.invalidFile }
    let metaCt = data.subdata(in: metaStart..<(metaStart + metaLen))
    let aad = header + senderPublic + enc
    let privateKey = recipientIdentity.privateKey
    let info = Self.buildInfo(header: header, senderPublic: senderPublic, recipientPublic: privateKey.publicKey.x963Representation)
    let senderKey = try P256.KeyAgreement.PublicKey(x963Representation: senderPublic)
    let recipient = try HPKE.Recipient(
      privateKey: privateKey,
      ciphersuite: .P256_SHA256_AES_GCM_256,
      info: info,
      encapsulatedKey: enc,
      authenticatedBy: senderKey
    )
    let metadataKey = try recipient.exportSymmetricKey(context: C.labelMetadataKey)
    let payloadKey = try recipient.exportSymmetricKey(context: C.labelPayloadKey)
    let metadata = try Self.decodeMetadata(Self.aesOpen(key: metadataKey, nonce: C.metadataNonce, aad: aad, ciphertext: metaCt))

    var plaintext = Data()
    var offset = metaStart + metaLen
    var index = 0
    while offset < data.count {
      let remaining = data.count - offset
      guard remaining >= C.gcmTagLength else { throw FileKeyCryptoError.invalidFile }
      let read = min(remaining, C.chunkSize + C.gcmTagLength)
      let isLast = offset + read >= data.count
      let chunkCt = data.subdata(in: offset..<(offset + read))
      let chunk = try Self.aesOpen(key: payloadKey, nonce: Self.chunkNonce(index: index, isLast: isLast), aad: aad, ciphertext: chunkCt)
      plaintext.append(chunk)
      offset += read
      index += 1
    }
    guard plaintext.count == metadata.originalSize else { throw FileKeyCryptoError.invalidFile }
    return (metadata, plaintext)
  }

  private static func encodeShareKey(publicBytes: Data) -> String {
    let namespaceTag = Data(SHA256.hash(data: Data(C.rpId.utf8))).prefix(4)
    let publicKey = try! P256.KeyAgreement.PublicKey(x963Representation: publicBytes)
    return Bech32m.encode(hrp: "fkey", data: [C.shareKeyVersion] + Array(namespaceTag) + Array(publicKey.compressedRepresentation))
  }

  static func decodeShareKey(_ shareKey: String) throws -> Data {
    let decoded = try Bech32m.decode(shareKey)
    guard decoded.hrp == "fkey", decoded.data.count == 38, decoded.data[0] == C.shareKeyVersion else {
      throw FileKeyCryptoError.invalidShareKey
    }
    let expectedTag = Array(Data(SHA256.hash(data: Data(C.rpId.utf8))).prefix(4))
    guard Array(decoded.data[1..<5]) == expectedTag else { throw FileKeyCryptoError.invalidShareKey }
    let compressed = Data(decoded.data[5..<38])
    return try P256.KeyAgreement.PublicKey(compressedRepresentation: compressed).x963Representation
  }

  private static func buildHeader() -> Data {
    Data(C.magic + Data([C.formatVersion, C.suiteId, 0x00, 0x00]) + Data(SHA256.hash(data: Data(C.rpId.utf8))).prefix(4))
  }

  private static func validateHeader(_ header: Data) throws {
    guard header.count == C.headerLength,
          header.prefix(4) == C.magic,
          header[4] == C.formatVersion,
          header[5] == C.suiteId,
          header[6] == 0,
          header[7] == 0,
          header[8..<12] == Data(SHA256.hash(data: Data(C.rpId.utf8))).prefix(4) else {
      throw FileKeyCryptoError.invalidFile
    }
  }

  private static func buildInfo(header: Data, senderPublic: Data, recipientPublic: Data) -> Data {
    Data(C.labelHPKEInfo.utf8) + header + senderPublic + recipientPublic + Data([UInt8(C.rpId.utf8.count)]) + Data(C.rpId.utf8)
  }

  private static func aesSeal(key: SymmetricKey, nonce: Data, aad: Data, plaintext: Data) throws -> Data {
    let box = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
    var out = Data()
    out.append(box.ciphertext)
    out.append(box.tag)
    return out
  }

  private static func aesOpen(key: SymmetricKey, nonce: Data, aad: Data, ciphertext: Data) throws -> Data {
    guard ciphertext.count >= C.gcmTagLength else { throw FileKeyCryptoError.invalidFile }
    do {
      let encrypted = ciphertext.prefix(ciphertext.count - C.gcmTagLength)
      let tag = ciphertext.suffix(C.gcmTagLength)
      let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: encrypted, tag: tag)
      return try AES.GCM.open(box, using: key, authenticating: aad)
    } catch {
      throw FileKeyCryptoError.authenticationFailed
    }
  }

  private static func encodeMetadata(_ metadata: FileKeyMetadata) -> Data {
    let filename = Data(metadata.filename.utf8)
    let mime = Data(metadata.mimeType.utf8)
    return Data([0x01]) + u32(filename.count) + filename + u32(mime.count) + mime + u64(metadata.originalSize) + u64(metadata.createdAtUnixMs) + Data([0x00, 0x00])
  }

  private static func decodeMetadata(_ data: Data) throws -> FileKeyMetadata {
    var offset = 0
    func take(_ n: Int) throws -> Data {
      guard offset + n <= data.count else { throw FileKeyCryptoError.invalidFile }
      defer { offset += n }
      return data.subdata(in: offset..<(offset + n))
    }
    guard try take(1)[0] == 0x01 else { throw FileKeyCryptoError.invalidFile }
    let filenameLen = Int(readU32(data, offset: offset))
    _ = try take(4)
    let filenameData = try take(filenameLen)
    let mimeLen = Int(readU32(data, offset: offset))
    _ = try take(4)
    let mimeData = try take(mimeLen)
    let size = Int(readU64(data, offset: offset))
    _ = try take(8)
    let created = Int(readU64(data, offset: offset))
    _ = try take(8)
    let extrasBytes = try take(2)
    let extras = (Int(extrasBytes[0]) << 8) | Int(extrasBytes[1])
    guard extras == 0, offset == data.count else { throw FileKeyCryptoError.invalidFile }
    return FileKeyMetadata(
      filename: String(data: filenameData, encoding: .utf8) ?? "file",
      mimeType: String(data: mimeData, encoding: .utf8) ?? "application/octet-stream",
      originalSize: size,
      createdAtUnixMs: created
    )
  }

  private static func chunkNonce(index: Int, isLast: Bool) -> Data {
    var nonce = Data(repeating: 0, count: 12)
    var value = index
    for i in stride(from: 10, through: 0, by: -1) {
      nonce[i] = UInt8(value & 0xff)
      value >>= 8
    }
    nonce[11] = isLast ? 1 : 0
    return nonce
  }

  private static func u32(_ n: Int) -> Data {
    Data([UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)])
  }

  private static func u64(_ n: Int) -> Data {
    var out = Data(repeating: 0, count: 8)
    var value = UInt64(n)
    for i in stride(from: 7, through: 0, by: -1) {
      out[i] = UInt8(value & 0xff)
      value >>= 8
    }
    return out
  }

  private static func readU32(_ data: Data, offset: Int) -> Int {
    (Int(data[offset]) << 24) | (Int(data[offset + 1]) << 16) | (Int(data[offset + 2]) << 8) | Int(data[offset + 3])
  }

  private static func readU64(_ data: Data, offset: Int) -> UInt64 {
    var value: UInt64 = 0
    for b in data[offset..<(offset + 8)] {
      value = (value << 8) | UInt64(b)
    }
    return value
  }

  private static func hkdfExtract(inputKeyMaterial: Data, salt: Data) -> SymmetricKey {
    let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: inputKeyMaterial), salt: salt)
    return SymmetricKey(data: prk.withUnsafeBytes { Data($0) })
  }

  private static func hkdfExpand(pseudoRandomKey: SymmetricKey, info: Data, outputByteCount: Int) -> Data {
    HKDF<SHA256>.expand(pseudoRandomKey: pseudoRandomKey, info: info, outputByteCount: outputByteCount).dataRepresentation
  }

  private static func labeledExtractKEM(salt: Data, label: String, ikm: Data) -> SymmetricKey {
    hkdfExtract(inputKeyMaterial: Data(C.hpkeVersionLabel.utf8) + C.kemSuiteId + Data(label.utf8) + ikm, salt: salt)
  }

  private static func labeledExpandKEM(pseudoRandomKey: SymmetricKey, label: String, info: Data, outputByteCount: Int) -> Data {
    let labeledInfo = u16(outputByteCount) + Data(C.hpkeVersionLabel.utf8) + C.kemSuiteId + Data(label.utf8) + info
    return hkdfExpand(pseudoRandomKey: pseudoRandomKey, info: labeledInfo, outputByteCount: outputByteCount)
  }

  private static func deriveP256PrivateKey(ikm: Data) throws -> P256.KeyAgreement.PrivateKey {
    let dkpPRK = labeledExtractKEM(salt: Data(), label: "dkp_prk", ikm: ikm)
    for counter in 0...255 {
      let candidate = labeledExpandKEM(pseudoRandomKey: dkpPRK, label: "candidate", info: Data([UInt8(counter)]), outputByteCount: 32)
      guard scalarIsValid(candidate) else { continue }
      do {
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: candidate)
      } catch {
        continue
      }
    }
    throw FileKeyCryptoError.authenticationFailed
  }

  private static let p256Order = Data([
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
  ])

  private static func scalarIsValid(_ candidate: Data) -> Bool {
    guard candidate.count == 32, candidate.contains(where: { $0 != 0 }) else { return false }
    return compareBigEndian(candidate, p256Order) < 0
  }

  private static func compareBigEndian(_ lhs: Data, _ rhs: Data) -> Int {
    let left = Array(lhs)
    let right = Array(rhs)
    for i in 0..<min(left.count, right.count) {
      if left[i] < right[i] { return -1 }
      if left[i] > right[i] { return 1 }
    }
    if left.count == right.count { return 0 }
    return left.count < right.count ? -1 : 1
  }

  private static func randomData(count: Int) throws -> Data {
    var data = Data(repeating: 0, count: count)
    let status = data.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
    }
    guard status == errSecSuccess else { throw FileKeyCryptoError.authenticationFailed }
    return data
  }

  private static func u16(_ n: Int) -> Data {
    Data([UInt8((n >> 8) & 0xff), UInt8(n & 0xff)])
  }
}

private extension HPKE.Sender {
  func exportSymmetricKey(context: String) throws -> SymmetricKey {
    try exportSecret(context: Data(context.utf8), outputByteCount: 32)
  }
}

private extension SymmetricKey {
  var dataRepresentation: Data {
    withUnsafeBytes { Data($0) }
  }
}

private extension HPKE.Recipient {
  func exportSymmetricKey(context: String) throws -> SymmetricKey {
    try exportSecret(context: Data(context.utf8), outputByteCount: 32)
  }
}
