import SwiftUI
import UniformTypeIdentifiers

struct InboxView: View {
  @Environment(AppModel.self) private var model
  @State private var objectId = ""

  var body: some View {
    List {
      Section("Open download") {
        TextField("Object id from /d/<id>", text: $objectId)
          .textInputAutocapitalization(.never)
          .autocorrectionDisabled()
        Button("Fetch file") {
          Task { await model.fetch(objectId: objectId) }
        }
        .disabled(objectId.isEmpty)
      }
      Section("Recent") {
        if model.inbox.isEmpty {
          ContentUnavailableView("No received files", systemImage: "tray")
        } else {
          ForEach(model.inbox) { item in
            HStack {
              VStack(alignment: .leading, spacing: 4) {
                Text(item.label)
                Text(item.size.map { "\($0) bytes" } ?? item.objectId)
                  .font(.caption)
                  .foregroundStyle(.secondary)
                Text(item.objectId)
                  .font(.caption2)
                  .foregroundStyle(.tertiary)
              }
              Spacer()
              if let url = model.localFileURL(for: item) {
                ShareLink(item: url) {
                  Label("Open", systemImage: "square.and.arrow.up")
                }
                .labelStyle(.iconOnly)
              }
            }
          }
        }
      }
    }
    .navigationTitle("Inbox")
  }
}

struct LinksView: View {
  @Environment(AppModel.self) private var model
  @State private var label = ""

  var body: some View {
    List {
      Section("Create") {
        TextField("Label", text: $label)
        Button {
          Task { await model.enrollPasskey(displayName: label) }
        } label: {
          Label("Create FileKey Passkey", systemImage: "person.badge.key")
        }
        Link(destination: EnvoyConfig.defaultWebBase) {
          Label("Create Drop Link on Web", systemImage: "safari")
        }
      }
      Section("Your links") {
        if model.links.isEmpty {
          ContentUnavailableView("No Drop links", systemImage: "link")
        } else {
          ForEach(model.links) { link in
            VStack(alignment: .leading, spacing: 8) {
              Text(link.label)
                .font(.headline)
              Text(link.shareURL.absoluteString)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
              HStack {
                ShareLink(item: link.shareURL) {
                  Label("Share", systemImage: "square.and.arrow.up")
                }
                Button(role: .destructive) {
                  Task { await model.revoke(link) }
                } label: {
                  Label("Revoke", systemImage: "trash")
                }
              }
              .buttonStyle(.bordered)
            }
          }
        }
      }
    }
    .navigationTitle("Links")
  }
}

struct SendView: View {
  @Environment(AppModel.self) private var model
  @State private var payload = UIPasteboard.general.string ?? ""
  @State private var importing = false
  @State private var selectedFile: URL?

  var body: some View {
    Form {
      Section("Drop link") {
        TextField("Paste link or fragment", text: $payload, axis: .vertical)
          .lineLimit(3...6)
          .textInputAutocapitalization(.never)
          .autocorrectionDisabled()
      }
      Section("File") {
        Button {
          importing = true
        } label: {
          Label(selectedFile?.lastPathComponent ?? "Choose File", systemImage: "doc")
        }
        Button {
          if let selectedFile {
            Task { await model.upload(fileURL: selectedFile, to: normalizedPayload) }
          }
        } label: {
          Label("Encrypt and Send", systemImage: "paperplane")
        }
        .disabled(selectedFile == nil || normalizedPayload.isEmpty)
      }
      Section("Transfers") {
        ForEach(model.transfers) { transfer in
          HStack {
            Image(systemName: transfer.status == .complete ? "checkmark.circle" : "exclamationmark.triangle")
            VStack(alignment: .leading) {
              Text(transfer.title)
              Text(transfer.status.rawValue.capitalized)
                .font(.caption)
                .foregroundStyle(.secondary)
            }
          }
        }
      }
    }
    .navigationTitle("Send")
    .fileImporter(isPresented: $importing, allowedContentTypes: [.item]) { result in
      selectedFile = try? result.get()
    }
  }

  private var normalizedPayload: String {
    if let fragment = URLComponents(string: payload)?.fragment {
      return fragment
    }
    return payload.trimmingCharacters(in: .whitespacesAndNewlines)
  }
}

struct SettingsView: View {
  var body: some View {
    Form {
      Section("Native Status") {
        Text("This branch uses the existing web API only. Native push, device registration, and native link creation are disabled.")
          .foregroundStyle(.secondary)
      }
    }
    .navigationTitle("Settings")
  }
}
