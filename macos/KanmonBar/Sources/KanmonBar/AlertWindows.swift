import AppKit
import SwiftUI

/// 警告の詳細ウィンドウ。閉じるまで最前面に残る。
@MainActor
final class AlertWindows {
    private var open: [String: NSPanel] = [:]

    func show(_ a: AlertItem) {
        if let w = open[a.id] {
            w.makeKeyAndOrderFront(nil)
            return
        }
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 460),
            styleMask: [.titled, .closable, .resizable, .utilityWindow],
            backing: .buffered,
            defer: false
        )
        panel.title = "kanmon — \(a.level.uppercased()) \(a.score)点"
        panel.level = .floating
        panel.isReleasedWhenClosed = false
        panel.contentView = NSHostingView(rootView: AlertDetailView(alert: a) { [weak self, weak panel] in
            panel?.close()
            self?.open[a.id] = nil
        })
        panel.center()
        open[a.id] = panel
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        if a.level == "critical" { NSSound.beep() }
    }
}

struct AlertDetailView: View {
    let alert: AlertItem
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: alert.level == "critical" ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                    .font(.system(size: 28))
                    .foregroundStyle(alert.level == "critical" ? Color.red : Color.orange)
                Text(alert.title)
                    .font(.headline)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ScrollView {
                Text(alert.body)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(8)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            HStack {
                Button("コピー") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString("\(alert.title)\n\n\(alert.body)", forType: .string)
                }
                Spacer()
                Button("OK", action: close)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(minWidth: 480, minHeight: 360)
    }
}
