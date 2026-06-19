import Foundation

enum EnvoyConfig {
  static let appGroup = "group.app.filekey.envoy"
  static let passkeyRelyingPartyID = "receive.link"
  static let defaultAPIBase = URL(string: "https://filekey-drop-staging.rockwellshah.workers.dev")!
  static let defaultWebBase = URL(string: "https://receive.link")!
  static let serverSignPublicJWK: [String: String] = [
    "crv": "P-256",
    "kty": "EC",
    "x": "wQspI1R3MyBRr0hPRba5LEbKH643Gbl0-EdqKbAVH1E",
    "y": "3twD-Dp7LZXQkJQQ_M8X9dN_LtaC2kUZ-Il6CR5gEcE"
  ]
}
