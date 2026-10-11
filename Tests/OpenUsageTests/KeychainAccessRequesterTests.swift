import XCTest
@testable import OpenUsage

final class KeychainAccessRequesterTests: XCTestCase {
    func testSecurityToolSpawnsSecurityWithLongTimeout() async throws {
        let item = KeychainItemRef(service: CursorAuthStore.keychainAccessTokenService, account: "rebers")
        let runner = RecordingProcess(result: ProcessResult(exitCode: 0, stdout: "secret\n", stderr: ""))
        let inspector = FakeInspector(inspection: .found(KeychainItemAccess(
            account: "rebers", securityReadsSilently: true, lastWriterIsSecurityTool: true
        )))
        let requester = makeRequester(runner: runner, inspector: inspector)

        let grant = await requester.request(item)

        XCTAssertEqual(grant, .granted)
        XCTAssertEqual(runner.calls.first, .init(
            executable: "/usr/bin/security",
            arguments: ["find-generic-password", "-s", item.service, "-a", item.account, "-w"],
            timeout: 600
        ))
    }

    func testOwnerAppSpawnsTheAppWithTheGrantFlag() async {
        let item = KeychainItemRef(service: CodexAuthStore.keychainService, account: "cli|abc")
        let runner = RecordingProcess(result: ProcessResult(exitCode: 0, stdout: "", stderr: ""))
        let inspector = FakeInspector(
            inspection: .found(KeychainItemAccess(account: "cli|abc", securityReadsSilently: false, lastWriterIsSecurityTool: false)),
            quiet: .value(Data("token".utf8))
        )
        let requester = makeRequester(runner: runner, inspector: inspector, appPath: "/Applications/OpenUsage.app/Contents/MacOS/OpenUsage")

        let grant = await requester.request(item)

        XCTAssertEqual(grant, .granted)
        XCTAssertEqual(runner.calls.map(\.executable), ["/Applications/OpenUsage.app/Contents/MacOS/OpenUsage"])
        XCTAssertEqual(runner.calls.map(\.arguments), [[KeychainGrantCommand.flag, item.service, item.account]])
        XCTAssertEqual(runner.calls.map(\.timeout), [600])
    }

    func testGrantMapping() async {
        let item = KeychainItemRef(service: CursorAuthStore.keychainAccessTokenService, account: "rebers")
        let silent = KeychainItemAccess(account: "rebers", securityReadsSilently: true, lastWriterIsSecurityTool: true)

        let granted = await grant(item, exit: 0, inspection: .found(silent), quiet: .notFound, stdout: "value\n")
        XCTAssertEqual(granted, .granted)

        let once = await grant(item, exit: 0, inspection: .found(KeychainItemAccess(
            account: "rebers", securityReadsSilently: false, lastWriterIsSecurityTool: true
        )))
        XCTAssertEqual(once, .allowedOnce)

        let denied = await grant(item, exit: 2, inspection: .found(KeychainItemAccess(
            account: "rebers", securityReadsSilently: false, lastWriterIsSecurityTool: true
        )))
        XCTAssertEqual(denied, .denied)

        let missing = await grant(item, exit: 0, inspection: .notFound)
        XCTAssertEqual(missing, .notFound)
    }

    private func grant(
        _ item: KeychainItemRef,
        exit: Int32,
        inspection: KeychainInspection,
        quiet: KeychainQuietRead = .notFound,
        stdout: String = ""
    ) async -> KeychainGrant {
        let runner = RecordingProcess(result: ProcessResult(exitCode: exit, stdout: stdout, stderr: ""))
        let requester = makeRequester(runner: runner, inspector: FakeInspector(inspection: inspection, quiet: quiet))
        return await requester.request(item)
    }

    private func makeRequester(
        runner: RecordingProcess,
        inspector: FakeInspector,
        appPath: String = "/tmp/OpenUsage"
    ) -> KeychainAccessRequester {
        KeychainAccessRequester(
            processRunner: runner,
            accessor: SecurityKeychainAccessor(
                inspector: inspector,
                processRunner: runner,
                ledger: KeychainAccessLedger(),
                currentUser: { "rebers" }
            ),
            appExecutablePath: appPath
        )
    }
}

final class KeychainGrantCommandTests: XCTestCase {
    func testNormalLaunchDoesNotParseAsGrant() {
        XCTAssertNil(KeychainGrantCommand.exitCode(for: ["/Applications/OpenUsage.app/Contents/MacOS/OpenUsage"]))
        XCTAssertNil(KeychainGrantCommand.exitCode(for: ["openusage"]))
    }

    func testWrongArityDoesNotParseAsGrant() {
        XCTAssertNil(KeychainGrantCommand.exitCode(for: ["exe", KeychainGrantCommand.flag, "service"]))
        XCTAssertNil(KeychainGrantCommand.exitCode(for: ["exe", "--other", "service", "account"]))
        XCTAssertNil(KeychainGrantCommand.exitCode(for: ["exe", KeychainGrantCommand.flag, "service", "account", "extra"]))
    }
}
