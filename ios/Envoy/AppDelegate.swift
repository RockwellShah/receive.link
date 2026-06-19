import UIKit
import UserNotifications

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
  func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    UNUserNotificationCenter.current().delegate = self
    return true
  }

  func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    Task { @MainActor in
      NotificationRegistration.shared.updateToken(deviceToken.map { String(format: "%02x", $0) }.joined())
    }
  }

  func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
    Task { @MainActor in
      NotificationRegistration.shared.registrationError = error.localizedDescription
    }
  }

  func userNotificationCenter(
    _ center: UNUserNotificationCenter,
    didReceive response: UNNotificationResponse
  ) async {
    if let urlString = response.notification.request.content.userInfo["url"] as? String,
       let url = URL(string: urlString) {
      await MainActor.run {
        NotificationRegistration.shared.pendingURL = url
      }
    }
  }
}

@MainActor
@Observable
final class NotificationRegistration {
  static let shared = NotificationRegistration()
  var apnsToken: String?
  var registrationError: String?
  var pendingURL: URL?

  func requestPermission() async {
    do {
      let granted = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound])
      if granted {
        await MainActor.run {
          UIApplication.shared.registerForRemoteNotifications()
        }
      }
    } catch {
      registrationError = error.localizedDescription
    }
  }

  func updateToken(_ token: String) {
    apnsToken = token
  }
}
