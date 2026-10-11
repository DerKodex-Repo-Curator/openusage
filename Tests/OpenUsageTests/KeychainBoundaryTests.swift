import XCTest

final class KeychainBoundaryTests: XCTestCase {
    func testKeychainSymbolsStayInTheKeychainFolder() throws {
        let sources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources")
        let needles = [
            "SecItemCopyMatching",
            "SecItemAdd",
            "SecItemUpdate",
            "SecKeychain",
            "\"/usr/bin/security\"",
        ]
        let allowed = "OpenUsage/Services/Keychain/"
        let files = try swiftFiles(under: sources)
        for needle in needles {
            let hits = files.filter { $0.text.contains(needle) }.map(\.relative)
            let outside = hits.filter { !$0.hasPrefix(allowed) }
            XCTAssertTrue(outside.isEmpty, "\(needle) outside \(allowed): \(outside)")
        }
        let interactionOn = files.filter { $0.text.contains("SecKeychainSetUserInteractionAllowed(true)") }
        XCTAssertTrue(interactionOn.isEmpty, "Keychain UI must never be turned back on")
        let live = files.filter { $0.text.contains("KeychainAccessRequester.live") }.map(\.relative)
        XCTAssertEqual(live, ["OpenUsage/App/AppContainer.swift"])
    }

    private func swiftFiles(under root: URL) throws -> [(relative: String, text: String)] {
        let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)!
        var files: [(String, String)] = []
        while let url = enumerator.nextObject() as? URL {
            guard url.pathExtension == "swift" else { continue }
            let text = try String(contentsOf: url, encoding: .utf8)
            let relative = url.path.replacingOccurrences(of: root.path + "/", with: "")
            files.append((relative, text))
        }
        return files
    }
}
