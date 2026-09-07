import SwiftUI

@main
struct EnvoyApp: App {
  @State private var model = AppModel()

  var body: some Scene {
    WindowGroup {
      AppView()
        .environment(model)
        .onOpenURL { url in
          model.handle(url: url)
        }
        .task {
          await model.start()
        }
    }
  }
}
