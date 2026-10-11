import XCTest
@testable import OpenUsage

@MainActor
final class ClaudeKeychainRefreshTests: XCTestCase {
    func testUnwritableKeychainTokenInsideTheWindowIsUsedWithoutRefresh() async throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let expiresAt = now.timeIntervalSince1970 * 1000 + 2 * 60 * 1000
        let http = RoutingHTTPClient { request in
            XCTAssertFalse(request.url.path.contains("/oauth/token"))
            XCTAssertEqual(request.headers["Authorization"], "Bearer still-good")
            return HTTPResponse(
                statusCode: 200, headers: [:],
                body: Data(#"{"five_hour":{"utilization":10,"resets_at":"2099-01-01T00:00:00.000Z"}}"#.utf8)
            )
        }
        let keychain = WritableFlagKeychain(canWrite: false)
        let provider = try makeProvider(keychain: keychain, token: "still-good", expiresAt: expiresAt, now: now, http: http)

        let snapshot = await provider.refresh()

        XCTAssertNil(snapshot.errorCategory)
        XCTAssertTrue(http.requests.allSatisfy { !$0.url.path.contains("/oauth/token") })
        XCTAssertTrue(keychain.writes.isEmpty)
    }

    func testUnwritableExpiredKeychainTokenThrowsWithoutRefresh() async throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let expiresAt = now.timeIntervalSince1970 * 1000 - 1_000
        let http = RoutingHTTPClient { _ in
            XCTFail("an expired keychain token must not be refreshed")
            return HTTPResponse(statusCode: 500, headers: [:], body: Data())
        }
        let provider = try makeProvider(
            keychain: WritableFlagKeychain(canWrite: false),
            token: "expired",
            expiresAt: expiresAt,
            now: now,
            http: http
        )

        let snapshot = await provider.refresh()

        XCTAssertEqual(snapshot.errorCategory, .authExpired)
        if case .badge(_, let text, _, _) = snapshot.lines.first {
            XCTAssertEqual(text, ClaudeAuthError.keychainTokenExpired.localizedDescription)
        } else {
            XCTFail("expected an error badge")
        }
        XCTAssertTrue(http.requests.isEmpty)
    }

    func testWritableKeychainTokenStillRefreshesAndSaves() async throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let expiresAt = now.timeIntervalSince1970 * 1000 + 60 * 1000
        let keychain = WritableFlagKeychain(canWrite: true)
        let http = RoutingHTTPClient { request in
            if request.url.path.hasSuffix("/v1/oauth/token") {
                return HTTPResponse(
                    statusCode: 200, headers: [:],
                    body: Data(#"{"access_token":"rotated","refresh_token":"rotated-refresh","expires_in":3600}"#.utf8)
                )
            }
            XCTAssertEqual(request.headers["Authorization"], "Bearer rotated")
            return HTTPResponse(
                statusCode: 200, headers: [:],
                body: Data(#"{"five_hour":{"utilization":10,"resets_at":"2099-01-01T00:00:00.000Z"}}"#.utf8)
            )
        }
        let provider = try makeProvider(keychain: keychain, token: "stale", expiresAt: expiresAt, now: now, http: http)

        let snapshot = await provider.refresh()

        XCTAssertNil(snapshot.errorCategory)
        XCTAssertEqual(http.requests.filter { $0.url.path.hasSuffix("/v1/oauth/token") }.count, 1)
        XCTAssertEqual(keychain.writes.count, 1)
        XCTAssertTrue(keychain.writes[0].contains("rotated-refresh"))
    }

    func testRefusedKeychainLoginWithLocalHistoryAsksForAccess() async throws {
        let now = Date(timeIntervalSince1970: 1_771_603_200)
        let home = try ClaudeLogFixture.makeHome(files: [
            "project/session.jsonl": ClaudeLogFixture.usageLine(timestamp: "2026-02-20T12:00:00Z", input: 100, output: 10)
        ])
        defer { try? FileManager.default.removeItem(at: home) }
        let http = RoutingHTTPClient { _ in
            XCTFail("no usage request without a readable login")
            return HTTPResponse(statusCode: 500, headers: [:], body: Data())
        }
        let provider = ClaudeProvider(
            authStore: ClaudeAuthStore(
                environment: FakeEnvironment([:]),
                files: FakeFiles(),
                keychain: RefusingKeychain(),
                now: { now }
            ),
            usageClient: ClaudeUsageClient(httpClient: http),
            logUsageScanner: ClaudeLogFixture.scanner(home: home),
            now: { now },
            pricing: { TestPricing.bundled }
        )

        let snapshot = await provider.refresh()

        XCTAssertEqual(snapshot.errorCategory, .credentialAccess)
        XCTAssertTrue(http.requests.isEmpty)
    }

    private func makeProvider(
        keychain: WritableFlagKeychain,
        token: String,
        expiresAt: Double,
        now: Date,
        http: RoutingHTTPClient
    ) throws -> ClaudeProvider {
        let authStore = ClaudeAuthStore(
            environment: FakeEnvironment([:]),
            files: FakeFiles(),
            keychain: keychain,
            now: { now }
        )
        let service = try XCTUnwrap(authStore.keychainServiceCandidates().first)
        keychain.currentUserValues[service] = """
        {"claudeAiOauth":{"accessToken":"\(token)","refreshToken":"refresh-me","expiresAt":\(expiresAt),"scopes":["user:profile"]}}
        """
        return ClaudeProvider(
            authStore: authStore,
            usageClient: ClaudeUsageClient(httpClient: http),
            logUsageScanner: ClaudeLogFixture.scanner(home: nil),
            now: { now },
            pricing: { TestPricing.bundled }
        )
    }
}

private struct RefusingKeychain: KeychainAccessing {
    func readGenericPassword(service: String) throws -> String? {
        throw KeychainError.accessNeeded(service: service)
    }

    func writeGenericPassword(service: String, value: String) throws {
        XCTFail("a refused login is never written")
    }
}

private final class WritableFlagKeychain: KeychainAccessing, @unchecked Sendable {
    var currentUserValues: [String: String] = [:]
    var writes: [String] = []
    let canWrite: Bool

    init(canWrite: Bool) { self.canWrite = canWrite }

    func readGenericPassword(service: String) throws -> String? { nil }

    func writeGenericPassword(service: String, value: String) throws {
        writes.append(value)
    }

    func readGenericPasswordForCurrentUser(service: String) throws -> String? {
        currentUserValues[service]
    }

    func writeGenericPasswordForCurrentUser(service: String, value: String) throws {
        writes.append(value)
        currentUserValues[service] = value
    }

    func canWriteWithSecurityTool(service: String) -> Bool {
        canWrite
    }

    func canWriteWithSecurityToolForCurrentUser(service: String) -> Bool {
        canWrite
    }
}
