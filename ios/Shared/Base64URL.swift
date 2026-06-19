import Foundation

enum Base64URL {
  static func encode(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  static func decode(_ string: String) throws -> Data {
    guard string.range(of: #"^[A-Za-z0-9_-]*$"#, options: .regularExpression) != nil else {
      throw DropLinkError.invalidBase64URL
    }
    let padded = string
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
      .padding(toLength: string.count + ((4 - string.count % 4) % 4), withPad: "=", startingAt: 0)
    guard let data = Data(base64Encoded: padded) else { throw DropLinkError.invalidBase64URL }
    return data
  }
}
