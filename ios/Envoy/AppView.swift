import SwiftUI

struct AppView: View {
  @Environment(AppModel.self) private var model

  var body: some View {
    @Bindable var model = model

    Group {
      if model.onboardingComplete {
        MainShellView()
      } else {
        NavigationStack {
          LinkSetupView(mode: .onboarding)
        }
      }
    }
    .sheet(item: $model.presentedSheet) { sheet in
      switch sheet {
      case let .linkReady(link):
        LinkReadySheet(link: link)
      case let .upload(request):
        UploadSheet(request: request)
      }
    }
    .alert("Envoy", isPresented: Binding(
      get: { model.statusMessage != nil },
      set: { if !$0 { model.statusMessage = nil } }
    )) {
      Button("OK", role: .cancel) { model.statusMessage = nil }
    } message: {
      Text(model.statusMessage ?? "")
    }
  }
}

private struct MainShellView: View {
  var body: some View {
    NavigationStack {
      InboxView()
        .toolbar {
          ToolbarItem(placement: .topBarTrailing) {
            NavigationLink {
              SettingsView()
            } label: {
              Image(systemName: "gear")
            }
            .accessibilityLabel("Settings")
          }
        }
    }
  }
}
