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
  private let notifications = NotificationRegistration.shared
  private let passkeys = PasskeyIdentityProvider.shared

  func start() async {
    links = store.loadLinks()
    inbox = store.loadInbox()
    await notifications.requestPermission()
    await registerDeviceIfPossible()
    if let pending = notifications.pendingURL {
      handle(url: pending)
      notifications.pendingURL = nil
    }
  }

  func createLink(label: String) async {
    do {
      await registerDeviceIfPossible()
      let install = store.loadInstall()
      let identity = try await passkeys.fileKeyIdentity()
      let shareKey = crypto.shareKey(identity: identity)
      let created = try await api.createNativeLink(installId: install.installId, shareKey: shareKey, label: label)
      let payload = try DropLinkCodec.decode(fragment: created.link)
      let record = DropLinkRecord(
        id: payload.linkId.hexString,
        label: label.isEmpty ? "Envoy Drop" : label,
        link: created.link,
        revokeToken: created.revokeToken,
        createdAt: Date(),
        emailFallbackVerified: false
      )
      store.upsert(record)
      links = store.loadLinks()
      statusMessage = "Drop link created."
    } catch {
      statusMessage = error.localizedDescription
    }
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
    do {
      let dropLink = try DropLinkCodec.verify(fragment: payload, publicJWK: EnvoyConfig.serverSignPublicJWK)
      let encrypted = try crypto.encryptForUpload(fileURL: fileURL, recipientShareKey: dropLink.shareKey)
      let initResponse = try await api.uploadInit(payload: payload, size: encrypted.count)
      guard initResponse.mode == "single", let uploadURL = initResponse.uploadUrl else {
        throw AppError.multipartPending
      }
      try await api.put(url: uploadURL, data: encrypted)
      try await api.uploadComplete(payload: payload, objectId: initResponse.objectId)
      transfers.insert(.init(id: UUID().uuidString, kind: .upload, title: fileURL.lastPathComponent, status: .complete, progress: 1, updatedAt: Date()), at: 0)
      statusMessage = "Upload complete."
    } catch {
      transfers.insert(.init(id: UUID().uuidString, kind: .upload, title: fileURL.lastPathComponent, status: .failed, progress: 0, updatedAt: Date()), at: 0)
      statusMessage = error.localizedDescription
    }
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

  private func registerDeviceIfPossible() async {
    var install = store.loadInstall()
    install.apnsToken = notifications.apnsToken ?? install.apnsToken ?? "simulator-token-\(install.installId)"
    store.saveInstall(install)
    do {
      try await api.registerDevice(install: install)
    } catch {
      statusMessage = "Device registration failed: \(error.localizedDescription)"
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
    case multipartPending
    var errorDescription: String? {
      "Native multipart upload support is not wired yet."
    }
  }
}

extension Data {
  var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
