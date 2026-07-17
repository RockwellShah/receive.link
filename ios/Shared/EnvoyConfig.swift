import Foundation

enum EnvoyConfig {
  static let appGroup = "group.app.filekey.envoy"
  static let passkeyRelyingPartyID = "receive.link"
  static let defaultAPIBase = URL(string: "https://filekey-drop-staging.rockwellshah.workers.dev")!
  static let defaultWebBase = URL(string: "https://receive.link")!
  static let serverKemPublicHex = "043b235d0c8594a8dda07e5db3ce127f697a65037aa606135c4ba80316b850833a524f6f78b35f98959887323342bdb93f6b7cc92e2ae92b556ffc5807c116b2b2"
  static let serverKemPublicKey = try! Data(hexEncoded: serverKemPublicHex)
  static let serverSignPublicJWK: [String: String] = [
    "crv": "P-256",
    "kty": "EC",
    "x": "wQspI1R3MyBRr0hPRba5LEbKH643Gbl0-EdqKbAVH1E",
    "y": "3twD-Dp7LZXQkJQQ_M8X9dN_LtaC2kUZ-Il6CR5gEcE"
  ]
}

extension Data {
  init(hexEncoded string: String) throws {
    var bytes: [UInt8] = []
    bytes.reserveCapacity(string.count / 2)

    var index = string.startIndex
    while index < string.endIndex {
      let next = string.index(index, offsetBy: 2, limitedBy: string.endIndex) ?? string.endIndex
      guard next <= string.endIndex,
            let byte = UInt8(string[index..<next], radix: 16) else {
        throw EnvoyConfigError.invalidHex
      }
      bytes.append(byte)
      index = next
    }

    self = Data(bytes)
  }
}

enum EnvoyConfigError: Error {
  case invalidHex
}
