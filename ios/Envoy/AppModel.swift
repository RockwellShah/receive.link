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
  var selectedTab: AppTab = .inbox
  var activeObjectId: String?

  private let store = SharedLinkStore.shared
  private let api = EnvoyAPI()
  private let crypto = FileKeyCrypto()
  private let passkeys = PasskeyIdentityProvider.shared

  func start() async {
    links = store.loadLinks()
    inbox = store.loadInbox()
  }

  func enrollPasskey(displayName: String) async {
    do {
      try await passkeys.enroll(displayName: displayName)
      statusMessage = "FileKey passkey is ready."
    } catch {
      statusMessage = error.localizedDescription
    }
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
      selectedTab = .inbox
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
    if url.pathComponents.contains("d"), let objectId = url.pathComponents.last {
      Task { await fetch(objectId: objectId) }
      return
    }
    if let fragment = URLComponents(url: url, resolvingAgainstBaseURL: false)?.fragment {
      selectedTab = .send
      statusMessage = "Drop link opened. Paste field is ready for sending."
      UIPasteboard.general.string = fragment
    }
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
}

extension Data {
  var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
