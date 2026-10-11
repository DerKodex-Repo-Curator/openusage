import XCTest
@testable import OpenUsage

final class KeychainACLDecisionTests: XCTestCase {
    func testSecurityCreatedItemIsSilentAndLastWriterIsSecurity() {
        let decrypt = [entry(["/usr/bin/security"])]
        let partitions = ["apple-tool:"]
        XCTAssertTrue(KeychainACLDecision.securityReadsSilently(decrypt: decrypt, partitions: partitions))
        XCTAssertTrue(KeychainACLDecision.lastWriterIsSecurityTool(partitions: partitions))
    }

    func testAlwaysAllowKeepsSecurityAsLastWriter() {
        let decrypt = [entry(["/usr/bin/security"])]
        let partitions = ["apple-tool:", "teamid:QC3D3H67V9"]
        XCTAssertTrue(KeychainACLDecision.securityReadsSilently(decrypt: decrypt, partitions: partitions))
        XCTAssertTrue(KeychainACLDecision.lastWriterIsSecurityTool(partitions: partitions))
    }

    func testInProcessOwnerIsNotSilent() {
        let decrypt = [entry(["/Applications/Codex.app"])]
        let partitions = ["teamid:Q6L2SF6YDW"]
        XCTAssertFalse(KeychainACLDecision.securityReadsSilently(decrypt: decrypt, partitions: partitions))
        XCTAssertFalse(KeychainACLDecision.lastWriterIsSecurityTool(partitions: partitions))
    }

    func testClaudeSafeStorageIsSilentButLastWriterIsNotSecurity() {
        let decrypt = [entry(["/usr/bin/security", "/Applications/Claude.app"])]
        let partitions = ["teamid:Q6L2SF6YDW", "cdhash:ab", "apple-tool:", "teamid:QC3D3H67V9", "apple:"]
        XCTAssertTrue(KeychainACLDecision.securityReadsSilently(decrypt: decrypt, partitions: partitions))
        XCTAssertFalse(KeychainACLDecision.lastWriterIsSecurityTool(partitions: partitions))
    }

    func testPassphraseEntryIsNotSilent() {
        let decrypt = [KeychainACLDecision.DecryptEntry(
            trustedApplicationPaths: ["/usr/bin/security"],
            requiresPassphrase: true
        )]
        let partitions = ["apple-tool:"]
        XCTAssertFalse(KeychainACLDecision.securityReadsSilently(decrypt: decrypt, partitions: partitions))
    }

    func testAnyAppWithMissingPartitionsIsNotSilent() {
        let decrypt = [KeychainACLDecision.DecryptEntry(trustedApplicationPaths: nil, requiresPassphrase: false)]
        XCTAssertFalse(KeychainACLDecision.securityReadsSilently(decrypt: decrypt, partitions: nil))
        XCTAssertFalse(KeychainACLDecision.lastWriterIsSecurityTool(partitions: nil))
    }

    func testPartitionHexRoundTrip() throws {
        let object = ["Partitions": ["apple-tool:", "teamid:QC3D3H67V9"]]
        let data = try PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
        let hex = data.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(KeychainPartitionList.parse(hexDescription: hex), ["apple-tool:", "teamid:QC3D3H67V9"])
        XCTAssertNil(KeychainPartitionList.parse(hexDescription: "abc"))
        XCTAssertNil(KeychainPartitionList.parse(hexDescription: ""))
    }

    func testQuietReadStatusMapping() {
        XCTAssertEqual(SystemKeychainItemInspector.classify(status: errSecSuccess, data: Data("ok".utf8)), .value(Data("ok".utf8)))
        XCTAssertEqual(SystemKeychainItemInspector.classify(status: errSecSuccess, data: nil), .failed(errSecSuccess))
        XCTAssertEqual(SystemKeychainItemInspector.classify(status: errSecItemNotFound, data: nil), .notFound)
        XCTAssertEqual(SystemKeychainItemInspector.classify(status: errSecAuthFailed, data: nil), .refused(errSecAuthFailed))
        XCTAssertEqual(
            SystemKeychainItemInspector.classify(status: errSecInteractionNotAllowed, data: nil),
            .refused(errSecInteractionNotAllowed)
        )
        XCTAssertEqual(SystemKeychainItemInspector.classify(status: errSecUserCanceled, data: nil), .refused(errSecUserCanceled))
        XCTAssertEqual(SystemKeychainItemInspector.classify(status: errSecDecode, data: nil), .failed(errSecDecode))
    }

    func testQuietUpdateStatusMapping() {
        XCTAssertEqual(SystemKeychainItemInspector.classify(updateStatus: errSecSuccess), .updated)
        XCTAssertEqual(SystemKeychainItemInspector.classify(updateStatus: errSecItemNotFound), .notFound)
        XCTAssertEqual(SystemKeychainItemInspector.classify(updateStatus: errSecAuthFailed), .refused(errSecAuthFailed))
        XCTAssertEqual(
            SystemKeychainItemInspector.classify(updateStatus: errSecInteractionNotAllowed),
            .refused(errSecInteractionNotAllowed)
        )
        XCTAssertEqual(SystemKeychainItemInspector.classify(updateStatus: errSecUserCanceled), .refused(errSecUserCanceled))
        XCTAssertEqual(SystemKeychainItemInspector.classify(updateStatus: errSecDecode), .failed(errSecDecode))
    }

    private func entry(_ paths: [String]) -> KeychainACLDecision.DecryptEntry {
        KeychainACLDecision.DecryptEntry(trustedApplicationPaths: paths, requiresPassphrase: false)
    }
}
