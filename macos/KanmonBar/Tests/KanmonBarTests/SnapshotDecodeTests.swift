import XCTest
@testable import KanmonBar

/// kanmond（Rust）との取り決めのテスト。Rust 側も同じ tests/fixtures/status-snapshot.json を検証する。
final class SnapshotDecodeTests: XCTestCase {
    func fixture(_ name: String = "status-snapshot.json") throws -> Data {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // KanmonBarTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // KanmonBar
            .deletingLastPathComponent()   // macos
            .deletingLastPathComponent()   // リポジトリのルート
            .appendingPathComponent("tests/fixtures/\(name)")
        return try Data(contentsOf: url)
    }

    func testDecodesDaemonSnapshot() throws {
        let s = try StatusClient.decodeSnapshot(try fixture())
        XCTAssertEqual(s.version, "0.1.0")
        XCTAssertEqual(s.counts24h["critical"], 1)
        XCTAssertEqual(s.counts24h["warn"], 2)
        XCTAssertEqual(s.learningUntil, "2026-11-25T10:00:00+09:00")
        XCTAssertEqual(s.eventsPath, "/Library/Logs/kanmon/events.jsonl")
        XCTAssertEqual(s.alerts.first?.level, "critical")
        XCTAssertTrue(s.alerts.first?.isSevere ?? false)
        XCTAssertNotNil(Fmt.date(s.alerts.first?.ts))
    }

    func testDecodesAlertList() throws {
        let l = try StatusClient.decodeAlertList(try fixture("status-alerts.json"))
        XCTAssertEqual(l.level, "notice")
        XCTAssertEqual(l.hours, 24)
        XCTAssertEqual(l.alerts.count, 2)
        XCTAssertEqual(l.alerts.first?.rules, ["N3"])
        XCTAssertNil(l.alerts.last?.rules)   // rules が無い警告も読める
        XCTAssertEqual(l.byRule["N3"], 1)
        XCTAssertFalse(l.truncated)
    }

    func testDecodesWithoutOptionalFields() throws {
        let json = """
        {"version":"0.1.0","host":"h","os":"macos","mode":"observe","learning":false,"learning_until":null,
         "started_at":"2026-11-18T12:00:00+09:00","detections":0,"intel":0,"counts_24h":{},"alerts":[],
         "last_event_at":null,"events_path":"/x"}
        """
        let s = try StatusClient.decodeSnapshot(Data(json.utf8))
        XCTAssertNil(s.learningUntil)
        XCTAssertTrue(s.counts24h.isEmpty)
    }

    func testDecodesExport() throws {
        let r = try StatusClient.decodeExport(try fixture("status-export.json"))
        XCTAssertEqual(r.count, 2)
        XCTAssertFalse(r.truncated)
        XCTAssertTrue(r.markdown.contains("| notice | 2 |"))
        XCTAssertEqual(r.sample.count, 1)
        XCTAssertNil(r.jsonl)
    }

    func testExportRequestLine() throws {
        var q = ExportRequest()
        q.format = "jsonl"
        q.pathsBasename = true
        let obj = try JSONSerialization.jsonObject(with: Data(q.line().utf8)) as? [String: Any]
        XCTAssertEqual(obj?["cmd"] as? String, "export")
        XCTAssertEqual(obj?["format"] as? String, "jsonl")
        XCTAssertEqual(obj?["paths"] as? String, "basename")
        XCTAssertEqual(obj?["min_level"] as? String, "notice")
        XCTAssertTrue(q.line().hasSuffix("\n"))
    }
}
