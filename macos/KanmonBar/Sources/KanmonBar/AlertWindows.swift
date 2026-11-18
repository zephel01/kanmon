import AppKit
import SwiftUI

/// 警告の詳細ウィンドウ。閉じるまで最前面に残る。
@MainActor
final class AlertWindows {
    private var open: [String: NSPanel] = [:]
    private var listWindow: NSWindow?

    /// 警告の一覧ウィンドウ（メニューの件数を押したとき）。1 つだけ開き、押したレベルに切り替える
    func showList(level: String, path: String) {
        let view = AlertListView(path: path, initialLevel: level) { [weak self] a in self?.show(a) }
        if let w = listWindow {
            w.contentView = NSHostingView(rootView: view)
            NSApp.activate(ignoringOtherApps: true)
            w.makeKeyAndOrderFront(nil)
            return
        }
        let w = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 680, height: 520),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        w.title = "kanmon — 警告の一覧（24時間）"
        w.isReleasedWhenClosed = false
        w.contentView = NSHostingView(rootView: view)
        w.center()
        listWindow = w
        NSApp.activate(ignoringOtherApps: true)
        w.makeKeyAndOrderFront(nil)
    }

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

private struct RuleCount: Identifiable {
    let id: String
    let count: Int
}

/// 警告の一覧。レベルの切り替え、ルール別の件数での絞り込み、文字列での検索ができる。行を押すと詳細
struct AlertListView: View {
    let path: String
    let openDetail: (AlertItem) -> Void
    @State private var level: String
    @State private var list: AlertList?
    @State private var error: String?
    @State private var loading = false
    @State private var query = ""
    @State private var rule: String?

    init(path: String, initialLevel: String, openDetail: @escaping (AlertItem) -> Void) {
        self.path = path
        self.openDetail = openDetail
        _level = State(initialValue: initialLevel)
    }

    private var rules: [RuleCount] {
        (list?.byRule ?? [:]).map { RuleCount(id: $0.key, count: $0.value) }
            .sorted { $0.count != $1.count ? $0.count > $1.count : $0.id < $1.id }
    }

    private var filtered: [AlertItem] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return (list?.alerts ?? []).filter { a in
            (rule == nil || (a.rules ?? []).contains(rule!))
                && (q.isEmpty || a.title.lowercased().contains(q) || a.body.lowercased().contains(q))
        }
    }

    private var statusLine: String {
        if loading { return "読み込み中…" }
        if let error { return error }
        guard let l = list else { return "" }
        var s = "\(filtered.count) 件を表示（全 \(l.alerts.count) 件"
        if l.truncated { s += "、上限で打ち切り" }
        return s + "）"
    }

    private func color(_ l: String) -> Color {
        switch l {
        case "critical": return .red
        case "warn": return .orange
        case "notice": return .yellow
        default: return .secondary
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Picker("レベル", selection: $level) {
                    Text("すべて").tag("all")
                    Text("critical").tag("critical")
                    Text("warn").tag("warn")
                    Text("notice").tag("notice")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 340)
                Spacer()
                Button {
                    load()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("読み直す")
            }
            TextField("検索（宛先・プロセス・理由）", text: $query)
                .textFieldStyle(.roundedBorder)
            if !rules.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(rules) { r in
                            Button {
                                rule = (rule == r.id) ? nil : r.id
                            } label: {
                                Text("\(r.id) \(r.count)")
                                    .font(.caption.monospacedDigit())
                                    .padding(.horizontal, 8).padding(.vertical, 3)
                                    .background(
                                        Capsule().fill(rule == r.id ? Color.accentColor.opacity(0.35)
                                                                    : Color.secondary.opacity(0.15))
                                    )
                            }
                            .buttonStyle(.plain)
                            .help("ルール \(r.id) で絞り込む（もう一度押すと解除）")
                        }
                    }
                }
            }
            Text(statusLine).font(.caption).foregroundStyle(.secondary)
            List(filtered) { a in
                Button {
                    openDetail(a)
                } label: {
                    HStack(spacing: 6) {
                        Circle().fill(color(a.level)).frame(width: 7, height: 7)
                        Text(Fmt.short(a.ts)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        Text(a.title.replacingOccurrences(of: "kanmon ", with: ""))
                            .lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 0)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(12)
        .frame(minWidth: 600, minHeight: 420)
        .onAppear { load() }
        .onChange(of: level) { _ in
            rule = nil
            load()
        }
    }

    private func load() {
        loading = true
        let p = path
        let lv = level
        Task.detached(priority: .userInitiated) {
            let r = StatusClient.fetchAlerts(path: p, level: lv)
            await MainActor.run {
                loading = false
                switch r {
                case .success(let l):
                    list = l
                    error = nil
                case .failure(let e):
                    error = e.description
                }
            }
        }
    }
}
