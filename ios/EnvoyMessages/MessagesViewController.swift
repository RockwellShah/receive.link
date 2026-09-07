import Messages
import UIKit

final class MessagesViewController: MSMessagesAppViewController {
  private let store = SharedLinkStore.shared

  override func willBecomeActive(with conversation: MSConversation) {
    super.willBecomeActive(with: conversation)
    render()
  }

  private func render() {
    let links = store.loadLinks()
    let stack = UIStackView()
    stack.axis = .vertical
    stack.spacing = 12
    stack.translatesAutoresizingMaskIntoConstraints = false

    let title = UILabel()
    title.text = "Envoy Links"
    title.font = .preferredFont(forTextStyle: .headline)
    stack.addArrangedSubview(title)

    if links.isEmpty {
      let empty = UILabel()
      empty.text = "Create a Drop link in Envoy first."
      empty.textColor = .secondaryLabel
      empty.numberOfLines = 0
      stack.addArrangedSubview(empty)
    } else {
      for link in links.prefix(5) {
        var configuration = UIButton.Configuration.borderedProminent()
        configuration.title = link.label
        configuration.subtitle = "Insert Drop link"
        let button = UIButton(configuration: configuration)
        button.addAction(UIAction { [weak self] _ in
          self?.insert(link)
        }, for: .touchUpInside)
        stack.addArrangedSubview(button)
      }
    }

    view.subviews.forEach { $0.removeFromSuperview() }
    view.addSubview(stack)
    NSLayoutConstraint.activate([
      stack.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor),
      stack.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor),
      stack.centerYAnchor.constraint(equalTo: view.centerYAnchor)
    ])
  }

  private func insert(_ link: DropLinkRecord) {
    guard let conversation = activeConversation else { return }
    let layout = MSMessageTemplateLayout()
    layout.caption = "Send files to \(link.label)"
    layout.subcaption = "End-to-end encrypted with Envoy"
    let message = MSMessage()
    message.url = link.shareURL
    message.layout = layout
    conversation.insert(message)
  }
}
