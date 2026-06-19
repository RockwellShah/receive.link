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

struct DropUploadRequest: Identifiable, Hashable {
  var id: String = UUID().uuidString
  var payload: String
  var label: String
}

enum PresentedSheet: Identifiable, Hashable {
  case linkReady(DropLinkRecord)
  case upload(DropUploadRequest)

  var id: String {
    switch self {
    case let .linkReady(link):
      return "link-ready-\(link.id)"
    case let .upload(request):
      return "upload-\(request.id)"
    }
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
