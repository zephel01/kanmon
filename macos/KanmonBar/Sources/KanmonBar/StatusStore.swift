import AppKit
import Foundation

/// 状態ソケットを定期的に読み、メニューバーの状態と警告ウィンドウを管理する。
@MainActor
final class StatusStore: ObservableObject {
    @Published private(set) var snapshot: Snapshot?
    @Published private(set) var error: String?
    @Published private(set) var lastOK: Date?

    /// 既読にした時刻。これより新しい警告があればアイコンを色付きにする
    @Published var acknowledged: Date {
        didSet { UserDefaults.standard.set(acknowledged.timeIntervalSince1970, forKey: "acknowledged") }
    }

    private var timer: Timer?
    private var seen = Set<String>()
    private var primed = false
    /// これより新しい警告だけをウィンドウで出す（アプリ起動時刻、または出した中で最新の時刻）。
    /// kanmond の再起動で DB から読み戻された古い警告を「新着」と誤認しないため
    private var popAfter = Date()
    let windows = AlertWindows()

    var socketPath: String {
        UserDefaults.standard.string(forKey: "socketPath") ?? StatusClient.defaultPath
    }

    init() {
        let t = UserDefaults.standard.double(forKey: "acknowledged")
        acknowledged = t > 0 ? Date(timeIntervalSince1970: t) : Date()
        // メニューを開く前から監視を始める
        DispatchQueue.main.async { [weak self] in self?.start() }
    }

    func start() {
        guard timer == nil else { return }
        refresh()
        let t = Timer(timeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    func refresh() {
        let path = socketPath
        Task.detached(priority: .utility) {
            let r = StatusClient.fetch(path: path)
            await MainActor.run { self.apply(r) }
        }
    }

    private func apply(_ r: Result<Snapshot, StatusClient.Failure>) {
        switch r {
        case .success(let s):
            snapshot = s
            error = nil
            lastOK = Date()
            popNewAlerts(s.alerts)
        case .failure(let e):
            error = e.description
        }
    }

    /// 新しく届いた warn 以上の警告をウィンドウで出す（起動直後の既存分は出さない）
    private func popNewAlerts(_ alerts: [AlertItem]) {
        let fresh = alerts.filter { !seen.contains($0.id) }
        fresh.forEach { seen.insert($0.id) }
        if !primed {
            primed = true
            return
        }
        let toPop = fresh.filter { a in
            a.isSevere && (Fmt.date(a.ts).map { $0 > popAfter } ?? false)
        }
        if let newest = toPop.compactMap({ Fmt.date($0.ts) }).max() {
            popAfter = newest
        }
        for a in toPop.prefix(3).reversed() {
            windows.show(a)
        }
    }

    var state: BarState {
        // 最後に読めてから 10 秒以上たったら「停止中の可能性」
        if let e = error, (lastOK.map { Date().timeIntervalSince($0) > 10 } ?? true) {
            return .down(e)
        }
        guard let s = snapshot else { return .down("未接続") }
        let unread = s.alerts.filter { (Fmt.date($0.ts) ?? .distantPast) > acknowledged }
        if unread.contains(where: \.isSevere) { return .alert }
        if !unread.isEmpty { return .notice }
        return .ok
    }

    var unreadCount: Int {
        snapshot?.alerts.filter { (Fmt.date($0.ts) ?? .distantPast) > acknowledged }.count ?? 0
    }

    var learningText: String? {
        guard let s = snapshot, s.learning else { return nil }
        guard let until = Fmt.date(s.learningUntil) else { return "学習期間中" }
        let days = max(0, Int(ceil(until.timeIntervalSinceNow / 86_400)))
        let f = DateFormatter()
        f.dateFormat = "M/d"
        return "学習期間：あと \(days) 日（\(f.string(from: until)) まで）"
    }

    func acknowledge() {
        acknowledged = Date()
    }

    func revealLog() {
        guard let p = snapshot?.eventsPath else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: p)])
    }
}
