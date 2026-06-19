import Foundation

@MainActor
final class SharedLinkStore {
  static let shared = SharedLinkStore()

  private let defaults: UserDefaults
  private let linksKey = "dropLinks.v1"
  private let inboxKey = "inboxItems.v1"

  init(defaults: UserDefaults = UserDefaults(suiteName: EnvoyConfig.appGroup) ?? .standard) {
    self.defaults = defaults
  }

  func loadLinks() -> [DropLinkRecord] {
    guard let data = defaults.data(forKey: linksKey) else { return [] }
    return (try? JSONDecoder().decode([DropLinkRecord].self, from: data)) ?? []
  }

  func saveLinks(_ links: [DropLinkRecord]) {
    let data = try? JSONEncoder().encode(links)
    defaults.set(data, forKey: linksKey)
  }

  func upsert(_ link: DropLinkRecord) {
    var links = loadLinks()
    links.removeAll { $0.id == link.id }
    links.insert(link, at: 0)
    saveLinks(links)
  }

  func loadInbox() -> [InboxItem] {
    guard let data = defaults.data(forKey: inboxKey) else { return [] }
    return (try? JSONDecoder().decode([InboxItem].self, from: data)) ?? []
  }

  func saveInbox(_ inbox: [InboxItem]) {
    let data = try? JSONEncoder().encode(inbox)
    defaults.set(data, forKey: inboxKey)
  }

  func upsert(_ item: InboxItem) {
    var inbox = loadInbox()
    inbox.removeAll { $0.id == item.id }
    inbox.insert(item, at: 0)
    saveInbox(inbox)
  }

  func writeInboxFile(data: Data, metadata: FileKeyMetadata, objectId: String) throws -> URL {
    let directory = try inboxDirectory()
    let filename = "\(safeFileComponent(objectId))-\(safeFileComponent(metadata.filename.isEmpty ? "file" : metadata.filename))"
    let url = directory.appendingPathComponent(filename, isDirectory: false)
    try data.write(to: url, options: .atomic)
    return url
  }

  func localFileURL(for item: InboxItem) -> URL? {
    guard let localFileName = item.localFileName,
          let directory = try? inboxDirectory() else {
      return nil
    }
    return directory.appendingPathComponent(localFileName, isDirectory: false)
  }

  private func inboxDirectory() throws -> URL {
    let base = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: EnvoyConfig.appGroup)
      ?? FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    let directory = base.appendingPathComponent("Inbox", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return directory
  }

  private func safeFileComponent(_ value: String) -> String {
    let invalid = CharacterSet(charactersIn: "/\\:").union(.controlCharacters)
    let cleaned = value.components(separatedBy: invalid).joined(separator: "_").trimmingCharacters(in: .whitespacesAndNewlines)
    return cleaned.isEmpty ? "file" : cleaned
  }
}
