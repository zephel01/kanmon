import XCTest
@testable import KanmonBar

/// kanmond（Rust）との取り決めのテスト。Rust 側も同じ tests/fixtures/status-snapshot.json を検証する。
final class SnapshotDecodeTests: XCTestCase {
    func fixture() throws -> Data {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // KanmonBarTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // KanmonBar
            .deletingLastPathComponent()   // macos
            .deletingLastPathComponent()   // リポジトリのルート
            .appendingPathComponent("tests/fixtures/status-snapshot.json")
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
}
