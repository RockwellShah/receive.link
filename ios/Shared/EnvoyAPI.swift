import Foundation

struct EnvoyAPI {
  var baseURL: URL = EnvoyConfig.defaultAPIBase
  var session: URLSession = .shared

  struct UploadPartURL: Codable, Hashable {
    var partNumber: Int
    var url: URL
  }

  struct UploadInit: Codable, Hashable {
    var mode: String
    var objectId: String
    var uploadUrl: URL?
    var uploadId: String?
    var partSize: Int?
    var partCount: Int?
    var partUrls: [UploadPartURL]?
    var batchSize: Int?
  }

  struct CreatedLink: Codable, Hashable {
    var link: String
    var revokeToken: String
    var emailConfirmationSent: Bool?
  }

  func registerDevice(install: NativeInstall) async throws {
    _ = try await post(path: "/native/register-device", body: [
      "installId": install.installId,
      "token": install.apnsToken ?? "simulator-token-\(install.installId)",
      "environment": install.environment
    ] as [String: String]) as EmptyResponse
  }

  func createNativeLink(installId: String, shareKey: String, label: String) async throws -> CreatedLink {
    try await post(path: "/native/create-link", body: [
      "installId": installId,
      "shareKey": Base64URL.encode(Data(shareKey.utf8)),
      "label": label
    ])
  }

  func revoke(token: String) async throws {
    _ = try await post(path: "/revoke", body: ["token": token]) as EmptyResponse
  }

  func uploadInit(payload: String, size: Int) async throws -> UploadInit {
    let body: [String: AnyEncodable] = ["payload": AnyEncodable(payload), "size": AnyEncodable(size)]
    return try await post(path: "/upload-init", body: body)
  }

  func uploadComplete(payload: String, objectId: String) async throws {
    _ = try await post(path: "/upload-complete", body: ["payload": payload, "objectId": objectId]) as EmptyResponse
  }

  func put(url: URL, data: Data) async throws {
    var request = URLRequest(url: url)
    request.httpMethod = "PUT"
    let (_, response) = try await session.upload(for: request, from: data)
    guard (response as? HTTPURLResponse)?.statusCode ?? 0 < 300 else { throw APIError.requestFailed }
  }

  func fetchURL(objectId: String) async throws -> URL {
    let url = baseURL.appending(path: "/fetch/\(objectId)")
    let (data, response) = try await session.data(from: url)
    guard (response as? HTTPURLResponse)?.statusCode ?? 0 < 300 else { throw APIError.requestFailed }
    return try JSONDecoder().decode(FetchResponse.self, from: data).url
  }

  private func post<T: Decodable, Body: Encodable>(path: String, body: Body) async throws -> T {
    var request = URLRequest(url: baseURL.appending(path: path))
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "content-type")
    request.httpBody = try JSONEncoder().encode(body)
    let (data, response) = try await session.data(for: request)
    guard (response as? HTTPURLResponse)?.statusCode ?? 0 < 300 else { throw APIError.requestFailed }
    return try JSONDecoder().decode(T.self, from: data)
  }

  private struct EmptyResponse: Decodable {}
  private struct FetchResponse: Decodable { var url: URL }

  enum APIError: Error, LocalizedError {
    case requestFailed
    var errorDescription: String? { "The Envoy API request failed." }
  }
}

struct AnyEncodable: Encodable, ExpressibleByStringLiteral, ExpressibleByIntegerLiteral {
  private let encodeValue: (Encoder) throws -> Void

  init(_ value: Encodable) {
    encodeValue = value.encode
  }

  init(stringLiteral value: String) {
    encodeValue = value.encode
  }

  init(integerLiteral value: Int) {
    encodeValue = value.encode
  }

  func encode(to encoder: Encoder) throws {
    try encodeValue(encoder)
  }
}
