import Foundation

struct EnvoyAPI {
  var baseURL: URL = EnvoyConfig.defaultAPIBase
  var session: URLSession = .shared

  struct UploadPartURL: Codable, Hashable {
    var partNumber: Int
    var url: URL
  }

  struct CompletedPart: Codable, Hashable {
    var partNumber: Int
    var etag: String
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

  struct ConfirmResponse: Codable, Hashable {
    var link: String
    var revokeToken: String
  }

  func register(sealedEmail: String, shareKey: String, label: String) async throws {
    let body = RegisterBody(sealedEmail: sealedEmail, shareKey: shareKey, label: label)
    _ = try await post(path: "/register", body: body) as EmptyResponse
  }

  func confirm(nonce: String) async throws -> ConfirmResponse {
    try await post(path: "/confirm", body: ["nonce": nonce])
  }

  func revoke(token: String) async throws {
    _ = try await post(path: "/revoke", body: ["token": token]) as EmptyResponse
  }

  func uploadInit(payload: String, size: Int) async throws -> UploadInit {
    let body: [String: AnyEncodable] = ["payload": AnyEncodable(payload), "size": AnyEncodable(size)]
    return try await post(path: "/upload-init", body: body)
  }

  func uploadParts(payload: String, objectId: String, from: Int, count: Int) async throws -> [UploadPartURL] {
    let body = UploadPartsBody(payload: payload, objectId: objectId, from: from, count: count)
    let response: UploadPartsResponse = try await post(path: "/upload-parts", body: body)
    return response.partUrls
  }

  func uploadComplete(payload: String, objectId: String, parts: [CompletedPart]? = nil) async throws {
    let body = UploadCompleteBody(payload: payload, objectId: objectId, parts: parts)
    var delay: UInt64 = 1_000_000_000
    for attempt in 0...4 {
      do {
        _ = try await post(path: "/upload-complete", body: body) as EmptyResponse
        return
      } catch let error as APIError where error.isRetryableCompletion && attempt < 4 {
        try await Task.sleep(nanoseconds: delay)
        delay *= 2
      }
    }
  }

  func uploadAbort(payload: String, objectId: String) async throws {
    _ = try await post(path: "/upload-abort", body: ["payload": payload, "objectId": objectId]) as EmptyResponse
  }

  func put(url: URL, data: Data) async throws {
    var request = URLRequest(url: url)
    request.httpMethod = "PUT"
    let (data, response) = try await session.upload(for: request, from: data)
    try validate(response: response, data: data, context: "PUT \(url.host ?? url.absoluteString)")
  }

  func putPart(url: URL, data: Data) async throws -> String {
    var request = URLRequest(url: url)
    request.httpMethod = "PUT"
    let (data, response) = try await session.upload(for: request, from: data)
    let http = try validate(response: response, data: data, context: "PUT part \(url.host ?? url.absoluteString)")
    guard let etag = http.value(forHTTPHeaderField: "ETag"), !etag.isEmpty else {
      throw APIError.missingETag
    }
    return etag
  }

  func fetchURL(objectId: String) async throws -> URL {
    let path = "/fetch/\(objectId)"
    let url = baseURL.appending(path: path)
    let (data, response) = try await session.data(from: url)
    try validate(response: response, data: data, context: "GET \(path)")
    return try JSONDecoder().decode(FetchResponse.self, from: data).url
  }

  private func post<T: Decodable, Body: Encodable>(path: String, body: Body) async throws -> T {
    var request = URLRequest(url: baseURL.appending(path: path))
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "content-type")
    request.httpBody = try JSONEncoder().encode(body)
    let (data, response) = try await session.data(for: request)
    try validate(response: response, data: data, context: "POST \(path)")
    return try JSONDecoder().decode(T.self, from: data)
  }

  @discardableResult
  private func validate(response: URLResponse, data: Data, context: String) throws -> HTTPURLResponse {
    guard let http = response as? HTTPURLResponse else {
      throw APIError.requestFailed(context: context, status: nil, body: "No HTTP response.")
    }
    guard http.statusCode < 300 else {
      throw APIError.requestFailed(context: context, status: http.statusCode, body: responseBody(data))
    }
    return http
  }

  private func responseBody(_ data: Data) -> String {
    guard !data.isEmpty else { return "Empty response body." }
    let value = String(data: data, encoding: .utf8) ?? "<\(data.count) bytes>"
    return value.count > 240 ? String(value.prefix(240)) + "..." : value
  }

  private struct EmptyResponse: Decodable {}
  private struct FetchResponse: Decodable { var url: URL }
  private struct RegisterBody: Encodable {
    var sealedEmail: String
    var shareKey: String
    var label: String
  }
  private struct UploadPartsBody: Encodable {
    var payload: String
    var objectId: String
    var from: Int
    var count: Int
  }
  private struct UploadPartsResponse: Decodable { var partUrls: [UploadPartURL] }
  private struct UploadCompleteBody: Encodable {
    var payload: String
    var objectId: String
    var parts: [CompletedPart]?
  }

  enum APIError: Error, LocalizedError {
    case requestFailed(context: String, status: Int?, body: String)
    case missingETag

    var isRetryableCompletion: Bool {
      switch self {
      case let .requestFailed(_, status, _):
        return status == 409 || status == 502
      case .missingETag:
        return false
      }
    }

    var errorDescription: String? {
      switch self {
      case let .requestFailed(context, status, body):
        if let status {
          return "Envoy API \(context) failed (\(status)): \(body)"
        }
        return "Envoy API \(context) failed: \(body)"
      case .missingETag:
        return "Storage accepted the upload but did not return an ETag."
      }
    }
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
