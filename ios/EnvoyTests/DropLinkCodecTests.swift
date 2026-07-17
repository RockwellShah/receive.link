import CryptoKit
import XCTest
@testable import Envoy

final class DropLinkCodecTests: XCTestCase {
  func testBase64URLRoundTrip() throws {
    let data = Data((0..<64).map(UInt8.init))
    XCTAssertEqual(try Base64URL.decode(Base64URL.encode(data)), data)
  }

  func testShareKeyHasExpectedPrefix() throws {
    let shareKey = FileKeyCrypto().shareKey(identity: makeIdentity("share-prefix"))
    XCTAssertTrue(shareKey.hasPrefix("fkey1"))
  }

  func testShareKeyDecodesToValidP256PublicKey() throws {
    let identity = makeIdentity("share")
    let publicKey = try FileKeyCrypto.decodeShareKey(FileKeyCrypto().shareKey(identity: identity))

    XCTAssertEqual(publicKey.count, 65)
    XCTAssertEqual(publicKey.first, UInt8(0x04))
    XCTAssertEqual(publicKey, identity.publicKeyBytes)
    XCTAssertNoThrow(try P256.KeyAgreement.PublicKey(x963Representation: publicKey))
  }

  func testPRFDerivedIdentityMatchesTypeScriptCoreVector() throws {
    let prfSecret = Data(SHA256.hash(data: Data("swift-web-prf-vector".utf8)))
    let identity = try FileKeyCrypto.identity(fromPRFSecret: prfSecret)

    XCTAssertEqual(
      FileKeyCrypto().shareKey(identity: identity),
      "fkey1q8ca8q23qgpt9rvkzmputnq2e3xy54kg88z63zqatm5luvtwj222xqgf52zhgryuku7"
    )
    XCTAssertEqual(
      identity.publicKeyBytes.hexString,
      "0402b28d9616c3c5cc0acc4c4a56c839c5a8881d5ee9fe316e9294a30109a285740485f08bca3e105b12d19323fb5510f381256904aa261ac6e71c71dfb1ab4fde"
    )
  }

  func testFileKeyRoundTripBetweenSeparatePRFDerivedIdentities() throws {
    let crypto = FileKeyCrypto()
    let sender = makeIdentity("sender")
    let receiver = makeIdentity("receiver")
    let plaintext = Data("hello from another native identity".utf8)
    let metadata = FileKeyMetadata(
      filename: "note.txt",
      mimeType: "text/plain",
      originalSize: 1,
      createdAtUnixMs: 1_700_000_000_000
    )

    let ciphertext = try crypto.encrypt(plaintext: plaintext, metadata: metadata, recipientShareKey: crypto.shareKey(identity: receiver), senderIdentity: sender)
    XCTAssertEqual(Array(ciphertext.prefix(4)), [0x46, 0x4b, 0x45, 0x59])

    let decrypted = try crypto.decrypt(ciphertext, recipientIdentity: receiver)
    XCTAssertEqual(decrypted.plaintext, plaintext)
    XCTAssertEqual(decrypted.metadata.filename, "note.txt")
    XCTAssertEqual(decrypted.metadata.mimeType, "text/plain")
    XCTAssertEqual(decrypted.metadata.originalSize, plaintext.count)
    XCTAssertEqual(decrypted.metadata.createdAtUnixMs, 1_700_000_000_000)
    XCTAssertThrowsError(try crypto.decrypt(ciphertext, recipientIdentity: sender))
  }

  func testFileKeyRoundTripAcrossChunkBoundary() throws {
    let crypto = FileKeyCrypto()
    let sender = makeIdentity("large-sender")
    let receiver = makeIdentity("large-receiver")
    let plaintext = Data((0..<70_000).map { UInt8($0 % 251) })
    let ciphertext = try crypto.encrypt(
      plaintext: plaintext,
      metadata: FileKeyMetadata(filename: "large.bin", mimeType: "application/octet-stream", originalSize: 0, createdAtUnixMs: 0),
      recipientShareKey: crypto.shareKey(identity: receiver),
      senderIdentity: sender
    )

    let decrypted = try crypto.decrypt(ciphertext, recipientIdentity: receiver)
    XCTAssertEqual(decrypted.plaintext, plaintext)
    XCTAssertEqual(decrypted.metadata.originalSize, plaintext.count)
  }

  func testFileKeyRoundTripToSelf() throws {
    let crypto = FileKeyCrypto()
    let identity = makeIdentity("self")
    let plaintext = Data("self encrypted".utf8)
    let ciphertext = try crypto.encrypt(
      plaintext: plaintext,
      metadata: FileKeyMetadata(filename: "self.txt", mimeType: "text/plain", originalSize: 0, createdAtUnixMs: 0),
      recipientShareKey: crypto.shareKey(identity: identity),
      senderIdentity: identity
    )

    let decrypted = try crypto.decrypt(ciphertext, recipientIdentity: identity)
    XCTAssertEqual(decrypted.plaintext, plaintext)
  }

  func testSealedEmailUsesHPKEEncThenCiphertextFormat() throws {
    let privateKey = P256.KeyAgreement.PrivateKey()
    let sealed = try FileKeyCrypto.sealEmail("receiver@example.com", serverKemPublicKey: privateKey.publicKey.x963Representation)

    XCTAssertGreaterThan(sealed.count, 65)
    let enc = sealed.prefix(65)
    let ciphertext = sealed.dropFirst(65)
    var recipient = try HPKE.Recipient(
      privateKey: privateKey,
      ciphersuite: .P256_SHA256_AES_GCM_256,
      info: FileKeyCrypto.emailSealInfo,
      encapsulatedKey: enc
    )
    let opened = try recipient.open(ciphertext)

    XCTAssertEqual(String(data: opened, encoding: .utf8), "receiver@example.com")
  }

  func testFileKeyRejectsTamperedCiphertext() throws {
    let crypto = FileKeyCrypto()
    let sender = makeIdentity("tamper-sender")
    let receiver = makeIdentity("tamper-receiver")
    let ciphertext = try crypto.encrypt(
      plaintext: Data("hello".utf8),
      metadata: FileKeyMetadata(filename: "hello.txt", mimeType: "text/plain", originalSize: 5, createdAtUnixMs: 0),
      recipientShareKey: crypto.shareKey(identity: receiver),
      senderIdentity: sender
    )
    var tampered = ciphertext
    tampered[tampered.count - 1] ^= 0x01

    XCTAssertThrowsError(try crypto.decrypt(tampered, recipientIdentity: receiver))
  }

  private func makeIdentity(_ suffix: String) -> FileKeyIdentity {
    try! FileKeyCrypto.identity(fromPRFSecret: Data(SHA256.hash(data: Data("test-prf-\(suffix)".utf8))))
  }
}
