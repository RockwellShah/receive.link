import Foundation

enum Bech32m {
  private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
  private static let charsetMap: [Character: UInt8] = Dictionary(uniqueKeysWithValues: charset.enumerated().map { ($0.element, UInt8($0.offset)) })
  private static let generator: [Int] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

  static func encode(hrp: String, data: [UInt8]) -> String {
    let values = try! convertBits(data, from: 8, to: 5, pad: true)
    let checksum = createChecksum(hrp: hrp, values: values)
    return hrp + "1" + (values + checksum).map { String(charset[Int($0)]) }.joined()
  }

  static func decode(_ string: String) throws -> (hrp: String, data: [UInt8]) {
    guard string == string.lowercased() || string == string.uppercased() else { throw Bech32mError.invalid }
    let lower = string.lowercased()
    guard let sep = lower.lastIndex(of: "1"), sep != lower.startIndex else { throw Bech32mError.invalid }
    let hrp = String(lower[..<sep])
    let valuesStart = lower.index(after: sep)
    let chars = lower[valuesStart...]
    guard chars.count >= 6 else { throw Bech32mError.invalid }
    let values = try chars.map { ch -> UInt8 in
      guard let v = charsetMap[ch] else { throw Bech32mError.invalid }
      return v
    }
    guard polymod(hrpExpand(hrp) + values) == 0x2bc830a3 else { throw Bech32mError.invalidChecksum }
    return (hrp, try convertBits(Array(values.dropLast(6)), from: 5, to: 8, pad: false))
  }

  private static func hrpExpand(_ hrp: String) -> [UInt8] {
    let scalars = Array(hrp.utf8)
    return scalars.map { $0 >> 5 } + [0] + scalars.map { $0 & 31 }
  }

  private static func polymod(_ values: [UInt8]) -> Int {
    var chk = 1
    for value in values {
      let top = chk >> 25
      chk = ((chk & 0x1ffffff) << 5) ^ Int(value)
      for i in 0..<5 where ((top >> i) & 1) == 1 {
        chk ^= generator[i]
      }
    }
    return chk
  }

  private static func createChecksum(hrp: String, values: [UInt8]) -> [UInt8] {
    let mod = polymod(hrpExpand(hrp) + values + Array(repeating: 0, count: 6)) ^ 0x2bc830a3
    return (0..<6).map { UInt8((mod >> (5 * (5 - $0))) & 31) }
  }

  private static func convertBits(_ data: [UInt8], from: Int, to: Int, pad: Bool) throws -> [UInt8] {
    var acc = 0
    var bits = 0
    let maxv = (1 << to) - 1
    var out: [UInt8] = []
    for value in data {
      guard Int(value) >> from == 0 else { throw Bech32mError.invalid }
      acc = (acc << from) | Int(value)
      bits += from
      while bits >= to {
        bits -= to
        out.append(UInt8((acc >> bits) & maxv))
      }
    }
    if pad, bits > 0 {
      out.append(UInt8((acc << (to - bits)) & maxv))
    }
    if !pad && (bits >= from || ((acc << (to - bits)) & maxv) != 0) {
      throw Bech32mError.invalid
    }
    return out
  }
}

enum Bech32mError: Error {
  case invalid
  case invalidChecksum
}
