import AppKit
import SwiftUI

@main
struct KanmonBarApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var store = StatusStore()

    var body: some Scene {
        MenuBarExtra {
            MenuView(store: store)
        } label: {
            Image(nsImage: BarIcon.image(for: store.state))
                .onAppear { store.start() }
        }
        .menuBarExtraStyle(.window)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Dock に出さない（Info.plist の LSUIElement と同じ効果。swift run 時のため）
        NSApp.setActivationPolicy(.accessory)
    }
}

/// メニューバーのアイコン。状態に応じて色を付ける（テンプレート画像にしない）
enum BarIcon {
    static func image(for state: BarState) -> NSImage {
        let color: NSColor
        switch state {
        case .ok: color = .labelColor
        case .notice: color = .systemYellow
        case .alert: color = .systemRed
        case .down: color = .systemGray
        }
        let base = NSImage(systemSymbolName: state.symbol, accessibilityDescription: "kanmon: \(state.label)")
            ?? NSImage(systemSymbolName: "shield", accessibilityDescription: "kanmon")!
        let cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .regular)
            .applying(NSImage.SymbolConfiguration(paletteColors: [color]))
        let img = base.withSymbolConfiguration(cfg) ?? base
        // 通常時は OS の配色（ライト/ダーク）に合わせる
        img.isTemplate = (state == .ok)
        return img
    }
}

struct MenuView: View {
    @ObservedObject var store: StatusStore

    private func levelColor(_ l: String) -> Color {
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
                Image(nsImage: BarIcon.image(for: store.state))
                VStack(alignment: .leading, spacing: 2) {
                    Text("kanmon \(store.snapshot?.version ?? "")").font(.headline)
                    Text(store.state.label).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if store.unreadCount > 0 {
                    Text("\(store.unreadCount)")
                        .font(.caption.bold())
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Capsule().fill(Color.red.opacity(0.85)))
                        .foregroundStyle(.white)
                }
            }

            if let s = store.snapshot {
                if let l = store.learningText {
                    Label(l, systemImage: "graduationcap").font(.caption)
                }
                HStack(spacing: 12) {
                    ForEach(["critical", "warn", "notice"], id: \.self) { lv in
                        Button {
                            store.windows.showList(level: lv, path: store.socketPath)
                        } label: {
                            HStack(spacing: 4) {
                                Circle().fill(levelColor(lv)).frame(width: 7, height: 7)
                                Text("\(lv) \(s.counts24h[lv] ?? 0)").font(.caption.monospacedDigit()).underline()
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help("押すと \(lv) の警告の一覧を開きます")
                    }
                    Spacer()
                    Text("24時間").font(.caption2).foregroundStyle(.secondary)
                }
                Divider()
                Text("直近の警告").font(.caption).foregroundStyle(.secondary)
                if s.alerts.isEmpty {
                    Text("ありません").font(.callout).foregroundStyle(.secondary)
                } else {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(s.alerts.prefix(10)) { a in
                            Button {
                                store.windows.show(a)
                            } label: {
                                HStack(spacing: 6) {
                                    Circle().fill(levelColor(a.level)).frame(width: 7, height: 7)
                                    Text(Fmt.short(a.ts)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                                    Text(a.title.replacingOccurrences(of: "kanmon ", with: ""))
                                        .font(.callout).lineLimit(1).truncationMode(.middle)
                                    Spacer(minLength: 0)
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                Divider()
                Text("検知ルール \(s.detections) 件 ・ 脅威インテル \(s.intel) 件 ・ \(s.host)")
                    .font(.caption2).foregroundStyle(.secondary)
            } else if let e = store.error {
                Label(e, systemImage: "exclamationmark.triangle").font(.callout)
                Text("kanmond が動いているか確認してください：\nsudo launchctl print system/com.kanmon.kanmond")
                    .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            }

            Divider()
            HStack {
                Button("既読にする") { store.acknowledge() }
                    .disabled(store.unreadCount == 0)
                Button("一覧") { store.windows.showList(level: "all", path: store.socketPath) }
                    .disabled(store.snapshot == nil)
                Button("ブラウザ") { store.openWeb() }
                    .disabled(store.snapshot == nil)
                    .help("脅威の履歴とプロセスのつながりをブラウザで見ます（このマシンだけ。読み取り専用）")
                Button("ログ") { store.revealLog() }
                    .disabled(store.snapshot == nil)
                    .help("ログのファイルを Finder で表示します")
                Button("書き出す…") { store.windows.showExport(path: store.socketPath) }
                    .disabled(store.snapshot == nil)
                    .help("IP・ホスト名などを伏せて、集計の表やログを書き出します（記事・Issue 向け）")
                Spacer()
                Button("終了") { store.stopWeb(); NSApp.terminate(nil) }
            }
            .font(.callout)
        }
        .padding(12)
        .frame(width: 400)
    }
}
