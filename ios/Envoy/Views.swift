import SwiftUI
import UIKit
import UniformTypeIdentifiers

enum LinkSetupMode {
  case onboarding
  case additional
}

private enum LinkSetupStage {
  case intro
  case details
  case checkEmail
}

struct LinkSetupView: View {
  @Environment(AppModel.self) private var model

  let mode: LinkSetupMode
  @State private var stage: LinkSetupStage
  @State private var email = ""
  @State private var label = ""
  @State private var confirmationLink = ""
  @State private var isWorking = false

  init(mode: LinkSetupMode) {
    self.mode = mode
    _stage = State(initialValue: mode == .onboarding ? .intro : .details)
  }

  var body: some View {
    Form {
      switch stage {
      case .intro:
        Section {
          Text("Create a link people can use to send you files.")
            .font(.headline)
          Text("Files are encrypted to your passkey. Envoy does not see files or store plain email.")
            .foregroundStyle(.secondary)
        }
        Section {
          Button("Continue") {
            stage = .details
          }
        }
      case .details:
        Section("Email") {
          TextField("you@example.com", text: $email)
            .keyboardType(.emailAddress)
            .textContentType(.emailAddress)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
        }
        Section("Sender-facing label") {
          TextField("Optional", text: $label)
        }
        Section {
          Button {
            Task { await register() }
          } label: {
            if isWorking {
              ProgressView()
            } else {
              Label("Create or Use Envoy Passkey", systemImage: "person.badge.key")
            }
          }
          .disabled(isWorking)
        }
      case .checkEmail:
        Section {
          Text("Check your email")
            .font(.headline)
          Text("Tap the confirmation link to finish setup and get your Drop link.")
            .foregroundStyle(.secondary)
        }
        Section("Paste confirmation link") {
          TextField("https://receive.link/confirm#...", text: $confirmationLink, axis: .vertical)
            .lineLimit(2...5)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
          Button {
            Task { await confirm() }
          } label: {
            if isWorking {
              ProgressView()
            } else {
              Label("Confirm", systemImage: "checkmark.circle")
            }
          }
          .disabled(isWorking || confirmationLink.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
      }
    }
    .navigationTitle(mode == .onboarding ? "Envoy" : "New Link")
  }

  private func register() async {
    isWorking = true
    defer { isWorking = false }
    if await model.registerDropLink(email: email, label: label) {
      stage = .checkEmail
    }
  }

  private func confirm() async {
    isWorking = true
    defer { isWorking = false }
    _ = await model.confirmSetup(from: confirmationLink)
  }
}

struct InboxView: View {
  @Environment(AppModel.self) private var model

  var body: some View {
    List {
      Section("Received") {
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

      if !model.transfers.isEmpty {
        Section("Activity") {
          ForEach(model.transfers) { transfer in
            HStack {
              Image(systemName: iconName(for: transfer.status))
                .foregroundStyle(iconColor(for: transfer.status))
              VStack(alignment: .leading) {
                Text(transfer.title)
                Text(transfer.status.rawValue.capitalized)
                  .font(.caption)
                  .foregroundStyle(.secondary)
              }
              Spacer()
              if transfer.status == .running {
                ProgressView(value: transfer.progress)
                  .frame(width: 72)
              }
            }
          }
        }
      }
    }
    .navigationTitle("Inbox")
  }

  private func iconName(for status: TransferRecord.Status) -> String {
    switch status {
    case .pending, .running: return "arrow.triangle.2.circlepath"
    case .complete: return "checkmark.circle"
    case .failed: return "exclamationmark.triangle"
    }
  }

  private func iconColor(for status: TransferRecord.Status) -> Color {
    switch status {
    case .pending, .running: return .secondary
    case .complete: return .green
    case .failed: return .orange
    }
  }
}

struct SettingsView: View {
  @Environment(AppModel.self) private var model

  var body: some View {
    Form {
      Section("Manage Links") {
        NavigationLink {
          LinkSetupView(mode: .additional)
        } label: {
          Label("Create New Drop Link", systemImage: "link.badge.plus")
        }

        if model.links.isEmpty {
          Text("No Drop links")
            .foregroundStyle(.secondary)
        } else {
          ForEach(model.links) { link in
            LinkManagementRow(link: link)
          }
        }
      }

      Section("Status") {
        Text("This branch uses the existing web API. Native push and device registration are disabled.")
          .foregroundStyle(.secondary)
      }
    }
    .navigationTitle("Settings")
  }
}

private struct LinkManagementRow: View {
  @Environment(AppModel.self) private var model

  let link: DropLinkRecord

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text(link.label)
        .font(.headline)
      Text(link.shareURL.absoluteString)
        .font(.caption)
        .foregroundStyle(.secondary)
        .lineLimit(3)
        .textSelection(.enabled)
      HStack {
        ShareLink(item: link.shareURL) {
          Label("Share", systemImage: "square.and.arrow.up")
        }
        Button {
          UIPasteboard.general.url = link.shareURL
          model.statusMessage = "Drop link copied."
        } label: {
          Label("Copy", systemImage: "doc.on.doc")
        }
        Button(role: .destructive) {
          Task { await model.revoke(link) }
        } label: {
          Label("Revoke", systemImage: "trash")
        }
      }
      .buttonStyle(.bordered)
    }
    .padding(.vertical, 4)
  }
}

struct LinkReadySheet: View {
  @Environment(AppModel.self) private var model

  let link: DropLinkRecord

  var body: some View {
    NavigationStack {
      Form {
        Section {
          Text("Your Drop link is ready.")
            .font(.headline)
          Text("Share it with anyone. Envoy will email you a download link when someone sends a file.")
            .foregroundStyle(.secondary)
        }
        Section("Drop link") {
          Text(link.shareURL.absoluteString)
            .font(.footnote)
            .textSelection(.enabled)
          ShareLink(item: link.shareURL) {
            Label("Share", systemImage: "square.and.arrow.up")
          }
          Button {
            UIPasteboard.general.url = link.shareURL
            model.statusMessage = "Drop link copied."
          } label: {
            Label("Copy", systemImage: "doc.on.doc")
          }
          Button("Done") {
            model.acknowledgeReadyLink()
          }
          .buttonStyle(.borderedProminent)
        }
      }
      .navigationTitle("Link Ready")
    }
  }
}

struct UploadSheet: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let request: DropUploadRequest
  @State private var importing = false
  @State private var selectedFile: URL?
  @State private var isSending = false

  var body: some View {
    NavigationStack {
      Form {
        Section("Drop link") {
          Text(request.label)
          Text(request.payload)
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(3)
        }

        Section("File") {
          Button {
            importing = true
          } label: {
            Label(selectedFile?.lastPathComponent ?? "Choose File", systemImage: "doc")
          }
          Button {
            Task { await send() }
          } label: {
            if isSending {
              ProgressView()
            } else {
              Label("Encrypt and Send", systemImage: "paperplane")
            }
          }
          .disabled(selectedFile == nil || isSending)
        }

        if !model.transfers.isEmpty {
          Section("Activity") {
            ForEach(model.transfers.prefix(3)) { transfer in
              VStack(alignment: .leading, spacing: 4) {
                Text(transfer.title)
                Text(transfer.status.rawValue.capitalized)
                  .font(.caption)
                  .foregroundStyle(.secondary)
                if transfer.status == .running {
                  ProgressView(value: transfer.progress)
                }
              }
            }
          }
        }
      }
      .navigationTitle("Send File")
      .toolbar {
        ToolbarItem(placement: .topBarTrailing) {
          Button("Done") {
            dismiss()
          }
        }
      }
      .fileImporter(isPresented: $importing, allowedContentTypes: [.item]) { result in
        selectedFile = try? result.get()
      }
    }
  }

  private func send() async {
    guard let selectedFile else { return }
    isSending = true
    defer { isSending = false }
    await model.upload(fileURL: selectedFile, to: request.payload)
  }
}
