import AppKit
import SwiftUI

/// 警告の詳細ウィンドウ。閉じるまで最前面に残る。
@MainActor
final class AlertWindows {
    private var open: [String: NSPanel] = [:]
    private var listWindow: NSWindow?
    private var listModel: AlertListModel?

    /// 警告の一覧ウィンドウ（メニューの件数を押したとき）。1 つだけ開き、押したレベルに切り替える
    func showList(level: String, path: String) {
        if let w = listWindow, let m = listModel {
            if m.level == level {
                m.load()
            } else {
                m.level = level  // didSet で読み直す
            }
            NSApp.activate(ignoringOtherApps: true)
            w.makeKeyAndOrderFront(nil)
            return
        }
        let model = AlertListModel(path: path, level: level)
        let view = AlertListView(model: model) { [weak self] a in self?.show(a) }
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
        listModel = model
        model.load()
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

struct RuleCount: Identifiable {
    let id: String
    let count: Int
}

/// 一覧ウィンドウの状態。`@State`（SwiftUI のマクロ）は Command Line Tools だけの環境で
/// ビルドできないため、ObservableObject と @Published（プロパティラッパー）で持つ。
@MainActor
final class AlertListModel: ObservableObject {
    let path: String
    @Published var level: String {
        didSet {
            if oldValue != level {
                rule = nil
                load()
            }
        }
    }
    @Published var list: AlertList?
    @Published var error: String?
    @Published var loading = false
    @Published var query = ""
    @Published var rule: String?

    init(path: String, level: String) {
        self.path = path
        self.level = level
    }

    var rules: [RuleCount] {
        (list?.byRule ?? [:]).map { RuleCount(id: $0.key, count: $0.value) }
            .sorted { $0.count != $1.count ? $0.count > $1.count : $0.id < $1.id }
    }

    var filtered: [AlertItem] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return (list?.alerts ?? []).filter { a in
            (rule == nil || (a.rules ?? []).contains(rule ?? ""))
                && (q.isEmpty || a.title.lowercased().contains(q) || a.body.lowercased().contains(q))
        }
    }

    var statusLine: String {
        if loading { return "読み込み中…" }
        if let error { return error }
        guard let l = list else { return "" }
        var s = "\(filtered.count) 件を表示（全 \(l.alerts.count) 件"
        if l.truncated { s += "、上限で打ち切り" }
        return s + "）"
    }

    func toggle(rule r: String) {
        rule = (rule == r) ? nil : r
    }

    func load() {
        loading = true
        let p = path
        let lv = level
        Task.detached(priority: .userInitiated) { [weak self] in
            let r = StatusClient.fetchAlerts(path: p, level: lv)
            await MainActor.run {
                guard let self else { return }
                // 読み込み中にレベルを切り替えた場合は、古い結果を捨てる
                guard self.level == lv else { return }
                self.loading = false
                switch r {
                case .success(let l):
                    self.list = l
                    self.error = nil
                case .failure(let e):
                    self.error = e.description
                }
            }
        }
    }
}

/// 警告の一覧。レベルの切り替え、ルール別の件数での絞り込み、文字列での検索ができる。行を押すと詳細
struct AlertListView: View {
    @ObservedObject var model: AlertListModel
    let openDetail: (AlertItem) -> Void

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
                Picker("レベル", selection: $model.level) {
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
                    model.load()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("読み直す")
            }
            TextField("検索（宛先・プロセス・理由）", text: $model.query)
                .textFieldStyle(.roundedBorder)
            if !model.rules.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(model.rules) { r in
                            Button {
                                model.toggle(rule: r.id)
                            } label: {
                                Text("\(r.id) \(r.count)")
                                    .font(.caption.monospacedDigit())
                                    .padding(.horizontal, 8).padding(.vertical, 3)
                                    .background(
                                        Capsule().fill(model.rule == r.id ? Color.accentColor.opacity(0.35)
                                                                          : Color.secondary.opacity(0.15))
                                    )
                            }
                            .buttonStyle(.plain)
                            .help("ルール \(r.id) で絞り込む（もう一度押すと解除）")
                        }
                    }
                }
            }
            Text(model.statusLine).font(.caption).foregroundStyle(.secondary)
            List(model.filtered) { a in
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
    }
}
