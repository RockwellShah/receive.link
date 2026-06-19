import AuthenticationServices
import CryptoKit
import Foundation
import Security
import UIKit

@MainActor
final class PasskeyIdentityProvider: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
  static let shared = PasskeyIdentityProvider()

  private var continuation: CheckedContinuation<ASAuthorization, Error>?
  private var activeController: ASAuthorizationController?

  func enroll(displayName: String) async throws {
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: EnvoyConfig.passkeyRelyingPartyID)
    let name = displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "FileKey" : displayName
    let request = provider.createCredentialRegistrationRequest(
      challenge: try randomData(count: 32),
      name: name,
      userID: try randomData(count: 16)
    )
    request.displayName = name
    request.userVerificationPreference = .required
    request.attestationPreference = .none
    request.prf = .checkForSupport

    let authorization = try await perform(request)
    guard let registration = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration,
          registration.prf?.isSupported == true else {
      throw PasskeyError.prfUnsupported
    }
  }

  func fileKeyIdentity() async throws -> FileKeyIdentity {
    let prfSecret = try await prfSecret()
    return try FileKeyCrypto.identity(fromPRFSecret: prfSecret)
  }

  private func prfSecret() async throws -> Data {
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: EnvoyConfig.passkeyRelyingPartyID)
    let request = provider.createCredentialAssertionRequest(challenge: try randomData(count: 32))
    request.userVerificationPreference = .required
    let values = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues.saltInput1(FileKeyCrypto.prfInputSalt())
    request.prf = .inputValues(values)

    let authorization = try await perform(request)
    guard let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion,
          let first = assertion.prf?.first else {
      throw PasskeyError.missingPRFOutput
    }
    return first.dataRepresentation
  }

  private func perform(_ request: ASAuthorizationRequest) async throws -> ASAuthorization {
    guard continuation == nil else { throw PasskeyError.requestInProgress }
    return try await withCheckedThrowingContinuation { continuation in
      self.continuation = continuation
      let controller = ASAuthorizationController(authorizationRequests: [request])
      self.activeController = controller
      controller.delegate = self
      controller.presentationContextProvider = self
      controller.performRequests()
    }
  }

  func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
    let continuation = continuation
    reset()
    continuation?.resume(returning: authorization)
  }

  func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
    let continuation = continuation
    reset()
    continuation?.resume(throwing: error)
  }

  func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
    let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
    return scenes.flatMap(\.windows).first(where: \.isKeyWindow) ?? UIWindow()
  }

  private func reset() {
    continuation = nil
    activeController = nil
  }

  private func randomData(count: Int) throws -> Data {
    var data = Data(repeating: 0, count: count)
    let status = data.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
    }
    guard status == errSecSuccess else { throw PasskeyError.randomFailed }
    return data
  }

  enum PasskeyError: Error, LocalizedError {
    case missingPRFOutput
    case prfUnsupported
    case randomFailed
    case requestInProgress

    var errorDescription: String? {
      switch self {
      case .missingPRFOutput:
        return "No passkey PRF output was returned. Create or use a FileKey passkey that supports PRF."
      case .prfUnsupported:
        return "This passkey provider does not support the PRF extension FileKey requires."
      case .randomFailed:
        return "Could not generate secure random bytes."
      case .requestInProgress:
        return "A passkey request is already in progress."
      }
    }
  }
}

private extension SymmetricKey {
  var dataRepresentation: Data {
    withUnsafeBytes { Data($0) }
  }
}
