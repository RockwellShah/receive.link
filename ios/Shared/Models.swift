import Foundation

struct DropLinkRecord: Identifiable, Codable, Hashable {
  var id: String
  var label: String
  var link: String
  var revokeToken: String
  var createdAt: Date
  var emailFallbackVerified: Bool

  var shareURL: URL {
    var components = URLComponents(url: EnvoyConfig.defaultWebBase, resolvingAgainstBaseURL: false)!
    components.fragment = link
    return components.url!
  }
}

struct InboxItem: Identifiable, Codable, Hashable {
  var id: String
  var objectId: String
  var label: String
  var receivedAt: Date
  var localFileName: String?
  var mimeType: String?
  var size: Int?
}

struct TransferRecord: Identifiable, Codable, Hashable {
  enum Kind: String, Codable { case upload, download }
  enum Status: String, Codable { case pending, running, complete, failed }

  var id: String
  var kind: Kind
  var title: String
  var status: Status
  var progress: Double
  var updatedAt: Date
}

struct NativeInstall: Codable, Hashable {
  var installId: String
  var apnsToken: String?
  var environment: String
}
