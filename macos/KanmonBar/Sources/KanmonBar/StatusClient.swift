import Foundation

/// kanmond の状態ソケット（Unix ドメインソケット）のクライアント。1 行送って 1 行受け取る。
enum StatusClient {
    static let defaultPath = "/var/run/kanmond.sock"

    enum Failure: Error, CustomStringConvertible {
        case socket(Int32)
        case connect(Int32)
        case io
        case server(String)
        case decode(String)

        var description: String {
            switch self {
            case .socket(let e): return "socket: \(String(cString: strerror(e)))"
            case .connect(let e) where e == ENOENT: return "ソケットがありません"
            case .connect(let e) where e == ECONNREFUSED: return "kanmond が応答しません"
            case .connect(let e): return "接続失敗: \(String(cString: strerror(e)))"
            case .io: return "読み書きに失敗"
            case .server(let m): return m == "forbidden" ? "接続が許可されていません" : "kanmond: \(m)"
            case .decode(let m): return "応答を解釈できません: \(m)"
            }
        }
    }

    static func fetch(path: String = defaultPath) -> Result<Snapshot, Failure> {
        let data: Data
        switch request(path: path, line: "{\"cmd\":\"status\"}\n") {
        case .success(let d): data = d
        case .failure(let e): return .failure(e)
        }
        if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let err = obj["error"] as? String {
            return .failure(.server(err))
        }
        do {
            return .success(try decodeSnapshot(data))
        } catch {
            return .failure(.decode(String(describing: error)))
        }
    }

    /// 警告の一覧（level は all / notice / warn / critical）
    static func fetchAlerts(path: String = defaultPath, level: String, hours: Int = 24, limit: Int = 1000)
        -> Result<AlertList, Failure>
    {
        let lv = ["all", "notice", "warn", "critical"].contains(level) ? level : "all"
        let line = "{\"cmd\":\"alerts\",\"level\":\"\(lv)\",\"hours\":\(hours),\"limit\":\(limit)}\n"
        let data: Data
        switch request(path: path, line: line) {
        case .success(let d): data = d
        case .failure(let e): return .failure(e)
        }
        if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let err = obj["error"] as? String {
            return .failure(.server(err == "unknown command" ? "kanmond が古い版です（一覧は v0.2.1 以降）" : err))
        }
        do {
            return .success(try decodeAlertList(data))
        } catch {
            return .failure(.decode(String(describing: error)))
        }
    }

    static func decodeAlertList(_ data: Data) throws -> AlertList {
        try JSONDecoder().decode(AlertList.self, from: data)
    }

    /// 状態の JSON を解釈する（テストからも使う）
    static func decodeSnapshot(_ data: Data) throws -> Snapshot {
        try JSONDecoder().decode(Snapshot.self, from: data)
    }

    private static func request(path: String, line: String) -> Result<Data, Failure> {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return .failure(.socket(errno)) }
        defer { close(fd) }

        var tv = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let cap = MemoryLayout.size(ofValue: addr.sun_path)
        let bytes = Array(path.utf8.prefix(cap - 1))
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else { return .failure(.connect(errno)) }

        let req = Array(line.utf8)
        let w = req.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        guard w == req.count else { return .failure(.io) }

        var out = Data()
        var buf = [UInt8](repeating: 0, count: 64 * 1024)
        while out.count < 8 * 1024 * 1024 {
            let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if n <= 0 { break }
            out.append(contentsOf: buf[0..<n])
            if out.last == 0x0A { break }
        }
        return out.isEmpty ? .failure(.io) : .success(out)
    }
}
