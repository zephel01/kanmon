// swift-tools-version: 5.9
// Kanmon.app（メニューバーアプリ）。kanmond の状態ソケットを読み、状態と警告を表示する。
// 将来は同じアプリに System Extension（Network Extension）を同梱する入れ物になる。
import PackageDescription

let package = Package(
    name: "KanmonBar",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "KanmonBar",
            path: "Sources/KanmonBar"
        )
    ]
)
