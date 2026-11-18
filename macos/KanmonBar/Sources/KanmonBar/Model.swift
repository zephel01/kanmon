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

    var isSevere: Bool { level == "warn" || level == "critical" }
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
