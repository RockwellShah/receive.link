import Foundation
import Observation
import UIKit

@MainActor
@Observable
final class AppModel {
  var links: [DropLinkRecord] = []
  var inbox: [InboxItem] = []
  var transfers: [TransferRecord] = []
  var statusMessage: String?
  var onboardingComplete = false
  var presentedSheet: PresentedSheet?
  var activeObjectId: String?
  var pendingConfirmationEmail: String?
  var pendingConfirmationLabel: String?

  private let store = SharedLinkStore.shared
  private let api = EnvoyAPI()
  private let crypto = FileKeyCrypto()
  private let passkeys = PasskeyIdentityProvider.shared

  func start() async {
    links = store.loadLinks()
    inbox = store.loadInbox()
    onboardingComplete = store.onboardingComplete() || !links.isEmpty
    if onboardingComplete {
      store.setOnboardingComplete(true)
    }
  }

  @discardableResult
  func registerDropLink(email: String, label: String) async -> Bool {
    let trimmedEmail = email.trimmingCharacters(in: .whitespacesAndNewlines)
    let trimmedLabel = label.trimmingCharacters(in: .whitespacesAndNewlines)
    guard Self.isValidEmail(trimmedEmail) else {
      statusMessage = "Enter an email address like you@example.com."
      return false
    }

    do {
      let displayName = trimmedLabel.isEmpty ? trimmedEmail : trimmedLabel
      let identity = try await passkeys.fileKeyIdentity(createIfNeeded: displayName)
      let shareKey = crypto.shareKey(identity: identity)
      let sealedEmail = try FileKeyCrypto.sealEmail(trimmedEmail, serverKemPublicKey: EnvoyConfig.serverKemPublicKey)
      try await api.register(
        sealedEmail: Base64URL.encode(sealedEmail),
        shareKey: Base64URL.encode(Data(shareKey.utf8)),
        label: trimmedLabel
      )
      pendingConfirmationEmail = trimmedEmail
      pendingConfirmationLabel = trimmedLabel
      statusMessage = nil
      return true
    } catch {
      statusMessage = error.localizedDescription
      return false
    }
  }

  @discardableResult
  func confirmSetup(from confirmationLink: String) async -> Bool {
    guard let nonce = Self.confirmationNonce(from: confirmationLink) else {
      statusMessage = "Paste the confirmation link from your email."
      return false
    }
    return await confirmSetup(nonce: nonce)
  }

  func acknowledgeReadyLink() {
    store.setOnboardingComplete(true)
    onboardingComplete = true
    presentedSheet = nil
  }

  func revoke(_ link: DropLinkRecord) async {
    do {
      try await api.revoke(token: link.revokeToken)
      var next = links
      next.removeAll { $0.id == link.id }
      store.saveLinks(next)
      links = next
      statusMessage = "Drop link turned off."
    } catch {
      statusMessage = error.localizedDescription
    }
  }

  func upload(fileURL: URL, to payload: String) async {
    let scoped = fileURL.startAccessingSecurityScopedResource()
    defer {
      if scoped { fileURL.stopAccessingSecurityScopedResource() }
    }
    let transferId = UUID().uuidString
    transfers.insert(.init(id: transferId, kind: .upload, title: fileURL.lastPathComponent, status: .running, progress: 0, updatedAt: Date()), at: 0)
    do {
      let dropLink = try DropLinkCodec.verify(fragment: payload, publicJWK: EnvoyConfig.serverSignPublicJWK)
      updateTransfer(id: transferId, status: .running, title: fileURL.lastPathComponent, progress: 0.1)
      let encrypted = try crypto.encryptForUpload(fileURL: fileURL, recipientShareKey: dropLink.shareKey)
      let initResponse = try await api.uploadInit(payload: payload, size: encrypted.count)
      if initResponse.mode == "single" {
        guard let uploadURL = initResponse.uploadUrl else { throw AppError.invalidUploadPlan }
        try await api.put(url: uploadURL, data: encrypted)
        try await api.uploadComplete(payload: payload, objectId: initResponse.objectId)
      } else if initResponse.mode == "multipart" {
        let parts = try await uploadMultipartParts(payload: payload, initResponse: initResponse, encrypted: encrypted, transferId: transferId)
        try await api.uploadComplete(payload: payload, objectId: initResponse.objectId, parts: parts)
      } else {
        throw AppError.invalidUploadPlan
      }
      updateTransfer(id: transferId, status: .complete, title: fileURL.lastPathComponent, progress: 1)
      statusMessage = "Upload complete."
    } catch {
      updateTransfer(id: transferId, status: .failed, title: fileURL.lastPathComponent, progress: 0)
      statusMessage = error.localizedDescription
    }
  }

  private func uploadMultipartParts(
    payload: String,
    initResponse: EnvoyAPI.UploadInit,
    encrypted: Data,
    transferId: String
  ) async throws -> [EnvoyAPI.CompletedPart] {
    guard let partSize = initResponse.partSize,
          let partCount = initResponse.partCount,
          let batchSize = initResponse.batchSize,
          partSize > 0,
          partCount > 0 else {
      throw AppError.invalidUploadPlan
    }

    var urls = Dictionary(uniqueKeysWithValues: (initResponse.partUrls ?? []).map { ($0.partNumber, $0.url) })
    var completed: [EnvoyAPI.CompletedPart] = []
    completed.reserveCapacity(partCount)

    do {
      for partNumber in 1...partCount {
        let start = (partNumber - 1) * partSize
        guard start < encrypted.count else { throw AppError.invalidUploadPlan }
        let end = min(start + partSize, encrypted.count)
        let bytes = encrypted.subdata(in: start..<end)
        let etag = try await uploadPartWithRetry(
          payload: payload,
          objectId: initResponse.objectId,
          partNumber: partNumber,
          batchSize: batchSize,
          bytes: bytes,
          urls: &urls
        )
        completed.append(.init(partNumber: partNumber, etag: etag))
        updateTransfer(id: transferId, status: .running, title: "Uploading part \(partNumber) of \(partCount)", progress: Double(partNumber) / Double(partCount))
      }
      return completed
    } catch {
      try? await api.uploadAbort(payload: payload, objectId: initResponse.objectId)
      throw error
    }
  }

  private func uploadPartWithRetry(
    payload: String,
    objectId: String,
    partNumber: Int,
    batchSize: Int,
    bytes: Data,
    urls: inout [Int: URL]
  ) async throws -> String {
    var delay: UInt64 = 500_000_000
    for attempt in 0..<5 {
      let url = try await uploadURL(payload: payload, objectId: objectId, partNumber: partNumber, batchSize: batchSize, urls: &urls)
      do {
        return try await api.putPart(url: url, data: bytes)
      } catch {
        urls[partNumber] = nil
        guard attempt < 4 else { throw error }
        try await Task.sleep(nanoseconds: delay)
        delay *= 2
      }
    }
    throw AppError.invalidUploadPlan
  }

  private func uploadURL(
    payload: String,
    objectId: String,
    partNumber: Int,
    batchSize: Int,
    urls: inout [Int: URL]
  ) async throws -> URL {
    if let url = urls[partNumber] {
      return url
    }
    let next = try await api.uploadParts(payload: payload, objectId: objectId, from: partNumber, count: batchSize)
    for part in next {
      urls[part.partNumber] = part.url
    }
    guard let url = urls[partNumber] else {
      throw AppError.missingPartURL(partNumber)
    }
    return url
  }

  func fetch(objectId: String) async {
    let transferId = UUID().uuidString
    transfers.insert(.init(id: transferId, kind: .download, title: objectId, status: .running, progress: 0, updatedAt: Date()), at: 0)
    do {
      let url = try await api.fetchURL(objectId: objectId)
      let (data, _) = try await URLSession.shared.data(from: url)
      let identity = try await passkeys.fileKeyIdentity()
      let decrypted = try crypto.decrypt(data, recipientIdentity: identity)
      let localURL = try store.writeInboxFile(data: decrypted.plaintext, metadata: decrypted.metadata, objectId: objectId)
      let item = InboxItem(
        id: objectId,
        objectId: objectId,
        label: decrypted.metadata.filename.isEmpty ? localURL.lastPathComponent : decrypted.metadata.filename,
        receivedAt: Date(),
        localFileName: localURL.lastPathComponent,
        mimeType: decrypted.metadata.mimeType,
        size: decrypted.plaintext.count
      )
      store.upsert(item)
      inbox = store.loadInbox()
      activeObjectId = objectId
      updateTransfer(id: transferId, status: .complete, title: item.label, progress: 1)
      statusMessage = "Decrypted \(item.label) (\(decrypted.plaintext.count) bytes)."
    } catch {
      updateTransfer(id: transferId, status: .failed, title: objectId, progress: 0)
      statusMessage = error.localizedDescription
    }
  }

  func localFileURL(for item: InboxItem) -> URL? {
    store.localFileURL(for: item)
  }

  func handle(url: URL) {
    if let nonce = Self.confirmationNonce(from: url) {
      Task { await confirmSetup(nonce: nonce) }
      return
    }

    if let objectId = Self.objectID(from: url) {
      Task { await fetch(objectId: objectId) }
      return
    }

    if let payload = Self.dropPayload(from: url) {
      presentUpload(payload: payload)
    }
  }

  func presentUpload(payload: String) {
    let normalized = Self.normalizedDropPayload(payload)
    do {
      let decoded = try DropLinkCodec.verify(fragment: normalized, publicJWK: EnvoyConfig.serverSignPublicJWK)
      let label = decoded.label.trimmingCharacters(in: .whitespacesAndNewlines)
      presentedSheet = .upload(.init(payload: normalized, label: label.isEmpty ? "Drop link" : label))
    } catch {
      statusMessage = error.localizedDescription
    }
  }

  private func confirmSetup(nonce: String) async -> Bool {
    do {
      let response = try await api.confirm(nonce: nonce)
      let record = makeLinkRecord(link: response.link, revokeToken: response.revokeToken)
      store.upsert(record)
      links = store.loadLinks()
      presentedSheet = .linkReady(record)
      statusMessage = nil
      return true
    } catch {
      statusMessage = error.localizedDescription
      return false
    }
  }

  private func makeLinkRecord(link: String, revokeToken: String) -> DropLinkRecord {
    let decoded = try? DropLinkCodec.verify(fragment: link, publicJWK: EnvoyConfig.serverSignPublicJWK)
    let decodedLabel = decoded?.label.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let pendingLabel = pendingConfirmationLabel?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return DropLinkRecord(
      id: decoded?.linkId.hexString ?? UUID().uuidString,
      label: decodedLabel.isEmpty ? (pendingLabel.isEmpty ? "Drop link" : pendingLabel) : decodedLabel,
      link: link,
      revokeToken: revokeToken,
      createdAt: Date(),
      emailFallbackVerified: true
    )
  }

  private func updateTransfer(id: String, status: TransferRecord.Status, title: String, progress: Double) {
    guard let index = transfers.firstIndex(where: { $0.id == id }) else { return }
    transfers[index].status = status
    transfers[index].title = title
    transfers[index].progress = progress
    transfers[index].updatedAt = Date()
  }

  enum AppError: Error, LocalizedError {
    case invalidUploadPlan
    case missingPartURL(Int)

    var errorDescription: String? {
      switch self {
      case .invalidUploadPlan:
        return "The upload server returned an invalid upload plan."
      case let .missingPartURL(partNumber):
        return "The upload server did not return a URL for part \(partNumber)."
      }
    }
  }

  private static func isValidEmail(_ value: String) -> Bool {
    value.range(of: #"^[^@\s]+@[^@\s]+\.[^@\s]+$"#, options: .regularExpression) != nil
  }

  private static func confirmationNonce(from value: String) -> String? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    if let url = URL(string: trimmed), let nonce = confirmationNonce(from: url) {
      return nonce
    }
    if trimmed.range(of: #"^[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil {
      return trimmed
    }
    return nil
  }

  private static func confirmationNonce(from url: URL) -> String? {
    let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    let isConfirmPath = url.path == "/confirm" || url.host == "confirm"
    guard isConfirmPath,
          let nonce = components?.fragment?.trimmingCharacters(in: .whitespacesAndNewlines),
          !nonce.isEmpty else {
      return nil
    }
    return nonce
  }

  private static func objectID(from url: URL) -> String? {
    let parts = url.pathComponents.filter { $0 != "/" }
    guard parts.count >= 2, parts[0] == "d" else { return nil }
    return parts[1]
  }

  private static func dropPayload(from url: URL) -> String? {
    guard url.path != "/confirm",
          url.path != "/revoke",
          url.host != "confirm",
          url.host != "revoke",
          let fragment = URLComponents(url: url, resolvingAgainstBaseURL: false)?.fragment else {
      return nil
    }
    let normalized = normalizedDropPayload(fragment)
    return normalized.isEmpty ? nil : normalized
  }

  private static func normalizedDropPayload(_ value: String) -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    if let fragment = URLComponents(string: trimmed)?.fragment {
      return fragment.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    return trimmed
  }
}

extension Data {
  var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
