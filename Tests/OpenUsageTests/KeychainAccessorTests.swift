import XCTest
@testable import OpenUsage

final class KeychainAccessorTests: XCTestCase {
    private let cursor = CursorAuthStore.keychainAccessTokenService
    private let own = "com.robinebers.openusage.icloud-sync-device-id.v1"

    func testSecurityReadUsesExactArgumentsAndStripsOneNewline() throws {
        let inspector = FakeInspector(inspection: .found(access(account: "rebers", silent: true, securityWrote: true)))
        let runner = RecordingProcess(result: ProcessResult(exitCode: 0, stdout: "secret\n", stderr: ""))
        let ledger = KeychainAccessLedger()
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: ledger)

        XCTAssertEqual(try accessor.readGenericPassword(service: cursor), "secret")
        XCTAssertEqual(runner.calls, [
            .init(executable: "/usr/bin/security", arguments: ["find-generic-password", "-s", cursor, "-a", "rebers", "-w"], timeout: 10)
        ])
        XCTAssertTrue(ledger.refusedItems(family: "cursor").isEmpty)
    }

    func testRefusedPreflightSpawnsNothingAndFillsTheLedger() {
        let inspector = FakeInspector(inspection: .found(access(account: "rebers", silent: false, securityWrote: true)))
        let runner = RecordingProcess()
        let ledger = KeychainAccessLedger()
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: ledger)

        XCTAssertThrowsError(try accessor.readGenericPassword(service: cursor)) { error in
            XCTAssertEqual(error as? KeychainError, .accessNeeded(service: cursor))
        }
        XCTAssertTrue(runner.calls.isEmpty)
        XCTAssertEqual(ledger.refusedItems(family: "cursor"), [KeychainItemRef(service: cursor, account: "rebers")])
    }

    func testLockedReadSpawnsNothing() {
        let inspector = FakeInspector(inspection: .locked)
        let runner = RecordingProcess()
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: KeychainAccessLedger())

        XCTAssertThrowsError(try accessor.readGenericPassword(service: cursor)) { error in
            XCTAssertEqual(error as? KeychainError, .locked)
        }
        XCTAssertTrue(runner.calls.isEmpty)
        XCTAssertEqual(inspector.inspectCount, 1)
    }

    func testSecurityExit44ReturnsNil() throws {
        let inspector = FakeInspector(inspection: .found(access(account: "rebers", silent: true, securityWrote: true)))
        let runner = RecordingProcess(result: ProcessResult(exitCode: 44, stdout: "", stderr: ""))
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: KeychainAccessLedger())

        XCTAssertNil(try accessor.readGenericPassword(service: cursor))
    }

    func testOwnerReadNeverSpawns() throws {
        let inspector = FakeInspector(
            inspection: .found(access(account: "Claude Key", silent: true, securityWrote: false)),
            quiet: .value(Data("desktop-key".utf8))
        )
        let runner = RecordingProcess()
        let ledger = KeychainAccessLedger()
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: ledger)

        XCTAssertEqual(
            try accessor.readGenericPassword(service: ClaudeDesktopSafeStorageKeyReader.service, account: "Claude Key"),
            "desktop-key"
        )
        XCTAssertTrue(runner.calls.isEmpty)
        XCTAssertEqual(inspector.quietCount, 1)
        XCTAssertTrue(ledger.refusedItems(family: "claude").isEmpty)
    }

    func testOwnerRefusalFillsTheLedger() {
        let service = CodexAuthStore.keychainService
        let inspector = FakeInspector(
            inspection: .found(access(account: "cli|abc", silent: false, securityWrote: false)),
            quiet: .refused(errSecAuthFailed)
        )
        let runner = RecordingProcess()
        let ledger = KeychainAccessLedger()
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: ledger)

        XCTAssertThrowsError(try accessor.readGenericPassword(service: service, account: "cli|abc")) { error in
            XCTAssertEqual(error as? KeychainError, .accessNeeded(service: service))
        }
        XCTAssertTrue(runner.calls.isEmpty)
        XCTAssertEqual(ledger.refusedItems(family: "codex"), [KeychainItemRef(service: service, account: "cli|abc")])
    }

    func testOwnerWriteUpdatesInProcessAndNeverSpawns() throws {
        let service = CodexAuthStore.keychainService
        let inspector = FakeInspector(
            inspection: .found(access(account: "cli|abc", silent: false, securityWrote: false)),
            update: .updated
        )
        let runner = RecordingProcess()
        let ledger = KeychainAccessLedger()
        ledger.noteRefused(KeychainItemRef(service: service, account: "cli|abc"))
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: ledger)

        try accessor.writeGenericPassword(service: service, account: "cli|abc", value: "rotated")

        XCTAssertEqual(inspector.updates, [.init(service: service, account: "cli|abc", data: Data("rotated".utf8))])
        XCTAssertTrue(runner.calls.isEmpty)
        XCTAssertTrue(ledger.refusedItems(family: "codex").isEmpty)
    }

    func testRefusedOwnerWriteFillsTheLedger() {
        let service = CodexAuthStore.keychainService
        let inspector = FakeInspector(
            inspection: .found(access(account: "cli|abc", silent: false, securityWrote: false)),
            update: .refused(errSecAuthFailed)
        )
        let runner = RecordingProcess()
        let ledger = KeychainAccessLedger()
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: ledger)

        XCTAssertThrowsError(try accessor.writeGenericPassword(service: service, account: "cli|abc", value: "rotated")) { error in
            XCTAssertEqual(error as? KeychainError, .accessNeeded(service: service))
        }
        XCTAssertTrue(runner.calls.isEmpty)
        XCTAssertEqual(ledger.refusedItems(family: "codex"), [KeychainItemRef(service: service, account: "cli|abc")])
    }

    func testMissingOwnerItemIsNotRecreated() {
        let inspector = FakeInspector(inspection: .notFound)
        let runner = RecordingProcess()
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: KeychainAccessLedger())

        XCTAssertThrowsError(try accessor.writeGenericPassword(
            service: CodexAuthStore.keychainService, account: "cli|abc", value: "rotated"
        )) { error in
            XCTAssertEqual(error as? KeychainError, .writeFailed("not recreating another app's sign-in"))
        }
        XCTAssertTrue(inspector.updates.isEmpty)
        XCTAssertTrue(runner.calls.isEmpty)
    }

    func testWriteBlockedByAnotherLastWriterDoesNotAskForAccess() {
        let inspector = FakeInspector(inspection: .found(access(account: "rebers", silent: true, securityWrote: false)))
        let runner = RecordingProcess()
        let ledger = KeychainAccessLedger()
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: ledger)

        XCTAssertThrowsError(try accessor.writeGenericPassword(service: cursor, value: "rotated")) { error in
            guard case .writeFailed = error as? KeychainError else { return XCTFail("unexpected \(error)") }
        }
        XCTAssertTrue(runner.calls.isEmpty)
        XCTAssertTrue(ledger.refusedItems(family: "cursor").isEmpty)
    }

    func testMissingForeignItemIsNotRecreated() {
        let inspector = FakeInspector(inspection: .notFound)
        let runner = RecordingProcess()
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: KeychainAccessLedger())

        XCTAssertThrowsError(try accessor.writeGenericPassword(service: cursor, account: "rebers", value: "new")) { error in
            XCTAssertEqual(error as? KeychainError, .writeFailed("not recreating another app's sign-in"))
        }
        XCTAssertTrue(runner.calls.isEmpty)
    }

    func testMissingOwnItemIsAddedWithoutUpdateFlag() throws {
        let inspector = FakeInspector(inspection: .notFound)
        let runner = RecordingProcess(result: ProcessResult(exitCode: 0, stdout: "", stderr: ""))
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: KeychainAccessLedger(), user: "tester")

        try accessor.writeGenericPasswordForCurrentUser(service: own, value: "ab")

        XCTAssertEqual(runner.calls, [
            .init(
                executable: "/usr/bin/security",
                arguments: ["add-generic-password", "-s", own, "-a", "tester", "-X", "6162"],
                timeout: 10
            )
        ])
    }

    func testSecurityWriteUsesUpdateFlagAndFoundAccount() throws {
        let inspector = FakeInspector(inspection: .found(access(account: "rebers", silent: true, securityWrote: true)))
        let runner = RecordingProcess(result: ProcessResult(exitCode: 0, stdout: "", stderr: ""))
        let accessor = makeAccessor(inspector: inspector, runner: runner, ledger: KeychainAccessLedger())

        try accessor.writeGenericPassword(service: cursor, value: "ab")

        XCTAssertEqual(runner.calls.map(\.arguments), [
            ["add-generic-password", "-U", "-s", cursor, "-a", "rebers", "-X", "6162"]
        ])
    }

    func testExistsThroughTheProtocolIsMetadataOnly() {
        let inspector = FakeInspector(
            inspection: .found(access(account: "rebers", silent: false, securityWrote: false)),
            quiet: .refused(errSecInteractionNotAllowed)
        )
        let runner = RecordingProcess()
        let ledger = KeychainAccessLedger()
        let keychain: any KeychainAccessing = makeAccessor(inspector: inspector, runner: runner, ledger: ledger)

        XCTAssertEqual(keychain.genericPasswordExists(service: CodexAuthStore.keychainService), true)
        XCTAssertEqual(inspector.quietCount, 0)
        XCTAssertTrue(runner.calls.isEmpty)
        XCTAssertTrue(ledger.refusedItems(family: "codex").isEmpty)
    }

    private func access(account: String, silent: Bool, securityWrote: Bool) -> KeychainItemAccess {
        KeychainItemAccess(account: account, securityReadsSilently: silent, lastWriterIsSecurityTool: securityWrote)
    }

    private func makeAccessor(
        inspector: FakeInspector,
        runner: RecordingProcess,
        ledger: KeychainAccessLedger,
        user: String = "rebers"
    ) -> SecurityKeychainAccessor {
        SecurityKeychainAccessor(inspector: inspector, processRunner: runner, ledger: ledger, currentUser: { user })
    }
}

final class FakeInspector: KeychainItemInspecting, @unchecked Sendable {
    struct Update: Equatable {
        var service: String
        var account: String
        var data: Data
    }

    var inspection: KeychainInspection
    var quiet: KeychainQuietRead
    var update: KeychainQuietUpdate
    private(set) var inspectCount = 0
    private(set) var quietCount = 0
    private(set) var updates: [Update] = []

    init(inspection: KeychainInspection, quiet: KeychainQuietRead = .notFound, update: KeychainQuietUpdate = .notFound) {
        self.inspection = inspection
        self.quiet = quiet
        self.update = update
    }

    func inspect(service: String, account: KeychainAccountSelector) -> KeychainInspection {
        inspectCount += 1
        return inspection
    }

    func readQuietly(service: String, account: KeychainAccountSelector) -> KeychainQuietRead {
        quietCount += 1
        return quiet
    }

    func updateQuietly(service: String, account: String, data: Data) -> KeychainQuietUpdate {
        updates.append(.init(service: service, account: account, data: data))
        return update
    }
}

final class RecordingProcess: ProcessRunning, @unchecked Sendable {
    struct Call: Equatable {
        var executable: String
        var arguments: [String]
        var timeout: TimeInterval
    }

    var calls: [Call] = []
    var result: ProcessResult
    var error: Error?

    init(result: ProcessResult = ProcessResult(exitCode: 0, stdout: "", stderr: ""), error: Error? = nil) {
        self.result = result
        self.error = error
    }

    func run(
        executable: String,
        arguments: [String],
        environment: [String: String],
        timeout: TimeInterval
    ) throws -> ProcessResult {
        calls.append(.init(executable: executable, arguments: arguments, timeout: timeout))
        if let error { throw error }
        return result
    }
}
