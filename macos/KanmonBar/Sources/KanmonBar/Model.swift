import Foundation

/// kanmond の状態ソケットが返す警告 1 件
struct AlertItem: Codable, Identifiable, Equatable {
    let id: String
    let ts: String
    let level: String
    let score: Int
    let kind: String
    let title: String
    let body: String
    /// 当たった検知ルールの ID（古い kanmond は返さない）
    let rules: [String]?

    var isSevere: Bool { level == "warn" || level == "critical" }
}

/// `{"cmd":"alerts"}` の応答：期間内の警告の一覧と、ルール別の件数
struct AlertList: Codable, Equatable {
    let level: String
    let hours: Int
    let alerts: [AlertItem]
    let byRule: [String: Int]
    let truncated: Bool

    enum CodingKeys: String, CodingKey {
        case level, hours, alerts, truncated
        case byRule = "by_rule"
    }
}

/// kanmond の状態スナップショット（`{"cmd":"status"}` の応答）
struct Snapshot: Codable, Equatable {
    let version: String
    let host: String
    let os: String
    let mode: String
    let learning: Bool
    let learningUntil: String?
    let startedAt: String
    let detections: Int
    let intel: Int
    let counts24h: [String: Int]
    let alerts: [AlertItem]
    let lastEventAt: String?
    let eventsPath: String

    /// kanmond の JSON は snake_case。`counts_24h` は Foundation の自動変換だと
    /// `counts24H` になって一致しないため、キーはすべて明示する。
    enum CodingKeys: String, CodingKey {
        case version, host, os, mode, learning, detections, intel, alerts
        case learningUntil = "learning_until"
        case startedAt = "started_at"
        case counts24h = "counts_24h"
        case lastEventAt = "last_event_at"
        case eventsPath = "events_path"
    }
}

/// メニューバーに出す状態
enum BarState: Equatable {
    case ok
    case notice
    case alert
    case down(String)

    var symbol: String {
        switch self {
        case .ok: return "checkmark.shield"
        case .notice: return "exclamationmark.shield"
        case .alert: return "exclamationmark.shield.fill"
        case .down: return "shield.slash"
        }
    }

    var label: String {
        switch self {
        case .ok: return "正常"
        case .notice: return "注意あり"
        case .alert: return "警告あり"
        case .down(let why): return "停止中の可能性（\(why)）"
        }
    }
}

enum Fmt {
    private static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
    private static let isoNoFrac = ISO8601DateFormatter()

    static func date(_ s: String?) -> Date? {
        guard let s else { return nil }
        return iso.date(from: s) ?? isoNoFrac.date(from: s)
    }

    static func short(_ s: String) -> String {
        guard let d = date(s) else { return s }
        let f = DateFormatter()
        f.dateFormat = Calendar.current.isDateInToday(d) ? "HH:mm" : "M/d HH:mm"
        return f.string(from: d)
    }
}
