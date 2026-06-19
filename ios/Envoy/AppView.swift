import SwiftUI

enum AppTab: String, CaseIterable, Identifiable {
  case inbox, links, send, settings
  var id: String { rawValue }

  var label: Label<Text, Image> {
    switch self {
    case .inbox: Label("Inbox", systemImage: "tray")
    case .links: Label("Links", systemImage: "link")
    case .send: Label("Send", systemImage: "paperplane")
    case .settings: Label("Settings", systemImage: "gear")
    }
  }
}

struct AppView: View {
  @Environment(AppModel.self) private var model

  var body: some View {
    @Bindable var model = model
    TabView(selection: $model.selectedTab) {
      NavigationStack { InboxView() }
        .tabItem { AppTab.inbox.label }
        .tag(AppTab.inbox)
      NavigationStack { LinksView() }
        .tabItem { AppTab.links.label }
        .tag(AppTab.links)
      NavigationStack { SendView() }
        .tabItem { AppTab.send.label }
        .tag(AppTab.send)
      NavigationStack { SettingsView() }
        .tabItem { AppTab.settings.label }
        .tag(AppTab.settings)
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
