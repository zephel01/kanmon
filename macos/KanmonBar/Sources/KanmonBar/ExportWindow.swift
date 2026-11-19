import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// 共有用の書き出しの状態。`@State`（SwiftUI のマクロ）は Command Line Tools だけの環境で
/// ビルドできないため、ObservableObject と @Published（プロパティラッパー）で持つ。
@MainActor
final class ExportModel: ObservableObject {
    let path: String
    @Published var req = ExportRequest() {
        didSet {
            if oldValue != req { load() }
        }
    }
    @Published var result: ExportResult?
    @Published var error: String?
    @Published var loading = false
    @Published var notice: String?
    private var generation = 0

    init(path: String) {
        self.path = path
    }

    /// プレビューに出す文字列（書き出す中身と同じもの）
    var preview: String {
        guard let r = result else { return "" }
        if req.format == "summary" { return r.markdown }
        if r.sample.isEmpty { return "（該当するイベントがありません）" }
        return "新しい順に \(r.sample.count) 件だけ表示しています（保存するのは全 \(r.count) 件）\n\n"
            + r.sample.joined(separator: "\n\n")
    }

    var statusLine: String {
        if loading { return "集計中…" }
        if let error { return error }
        guard let r = result else { return "" }
        var s = "\(r.count) 件（伏せ済み）"
        if r.truncated { s += "・上限で打ち切り" }
        return s
    }

    func load() {
        loading = true
        notice = nil
        generation += 1
        let gen = generation
        let p = path
        let r = req
        Task.detached(priority: .userInitiated) { [weak self] in
            let out = StatusClient.export(path: p, request: r)
            await MainActor.run {
                guard let self, self.generation == gen else { return }
                self.loading = false
                switch out {
                case .success(let v):
                    self.result = v
                    self.error = nil
                case .failure(let e):
                    self.result = nil
                    self.error = e.description
                }
            }
        }
    }

    func copyMarkdown() {
        guard let r = result else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(r.markdown, forType: .string)
        notice = "集計の表をコピーしました"
    }

    func save() {
        guard let r = result else { return }
        let isLog = req.format == "jsonl"
        let panel = NSSavePanel()
        let stamp = DateFormatter()
        stamp.dateFormat = "yyyyMMdd-HHmm"
        let name = "kanmon-\(isLog ? "log" : "summary")-\(stamp.string(from: Date()))"
        panel.nameFieldStringValue = name + (isLog ? ".jsonl" : ".md")
        panel.allowedContentTypes = isLog ? [UTType(filenameExtension: "jsonl") ?? .json] : [UTType(filenameExtension: "md") ?? .plainText]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let text = isLog ? (r.jsonl ?? "") : r.markdown
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            notice = "\(url.lastPathComponent) に保存しました"
        } catch {
            self.error = "保存できませんでした：\(error.localizedDescription)"
        }
    }
}

/// 共有用の書き出しの画面：条件を選ぶ → プレビューで確かめる → コピー・保存
struct ExportView: View {
    @ObservedObject var model: ExportModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("IP・ホスト名・ユーザー名・ホームのパス・コマンドの引数は伏せて書き出します。共有する前にプレビューを確かめてください。")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                GridRow {
                    Text("期間")
                    Picker("期間", selection: $model.req.hours) {
                        Text("1 時間").tag(1)
                        Text("24 時間").tag(24)
                        Text("7 日").tag(24 * 7)
                    }
                    .pickerStyle(.segmented).labelsHidden().frame(width: 260)
                }
                GridRow {
                    Text("含めるもの")
                    Picker("含めるもの", selection: $model.req.minLevel) {
                        Text("全部").tag("info")
                        Text("notice 以上").tag("notice")
                        Text("warn 以上").tag("warn")
                    }
                    .pickerStyle(.segmented).labelsHidden().frame(width: 260)
                }
                GridRow {
                    Text("形式")
                    Picker("形式", selection: $model.req.format) {
                        Text("集計の表（記事向け）").tag("summary")
                        Text("伏せたログ（Issue 向け）").tag("jsonl")
                    }
                    .pickerStyle(.radioGroup).labelsHidden()
                }
                GridRow {
                    Text("ドメイン")
                    Picker("ドメイン", selection: $model.req.domains) {
                        Text("登録ドメインだけ残す").tag("registered")
                        Text("全部伏せる").tag("mask")
                        Text("そのまま残す").tag("keep")
                    }
                    .labelsHidden().frame(width: 220)
                }
                GridRow {
                    Text("")
                    VStack(alignment: .leading, spacing: 4) {
                        Toggle("時刻を 1 時間単位に丸める", isOn: $model.req.roundTime)
                        Toggle("パスをファイル名だけにする", isOn: $model.req.pathsBasename)
                    }
                }
            }
            HStack {
                Text(model.statusLine).font(.caption).foregroundStyle(model.error == nil ? Color.secondary : Color.red)
                Spacer()
                Button {
                    model.load()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("読み直す")
            }
            ScrollView {
                Text(model.preview)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(8)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            HStack {
                if let n = model.notice {
                    Text(n).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("表をコピー") { model.copyMarkdown() }
                    .disabled(model.result == nil)
                Button("保存…") { model.save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.result == nil || model.loading)
            }
        }
        .padding(14)
        .frame(minWidth: 620, minHeight: 560)
    }
}
