import XCTest
@testable import OpenUsage

@MainActor
final class CodexKeychainCardTests: XCTestCase {
    func testRefusedCodexAuthReadKeepsTheExistingAccountCard() async throws {
        let identity = try XCTUnwrap(CodexAccountIdentity(accountID: "workspace-a", email: "personal@example.com"))
        let defaults = try makeDefaults()
        let accounts = ProviderAccountsStore(defaults: defaults)
        accounts.reconcile(with: [.init(
            family: "codex",
            identityKey: identity.key,
            label: identity.email,
            sources: [.init(kind: .defaultHome, anchor: nil, holdsDefaultSource: true)]
        )])
        let keychain = RefusingCodexKeychain()
        defer { KeychainAccessLedger.shared.noteMissing(service: CodexAuthStore.keychainService, account: nil) }
        let home = URL(fileURLWithPath: "/openusage-codex-card-fixture")
        let discovery = await ProviderAccountAssembly.makeCodexCards(
            observer: DefaultAccountObserver(
                environment: FakeEnvironment([:]),
                files: FakeFiles(),
                keychain: keychain,
                homeDirectory: { home }
            ),
            accountsStore: accounts,
            listDirectories: { _ in [] }
        )

        XCTAssertEqual(discovery.cards.map(\.identity), [identity])
        XCTAssertEqual(accounts.records.map(\.identityKey), [identity.key])
    }

    func testMissingCodexAuthReadDoesNotInventACard() async throws {
        let identity = try XCTUnwrap(CodexAccountIdentity(accountID: "workspace-a", email: "personal@example.com"))
        let defaults = try makeDefaults()
        let accounts = ProviderAccountsStore(defaults: defaults)
        accounts.reconcile(with: [.init(
            family: "codex",
            identityKey: identity.key,
            label: identity.email,
            sources: [.init(kind: .defaultHome, anchor: nil, holdsDefaultSource: true)]
        )])
        let home = URL(fileURLWithPath: "/openusage-codex-card-fixture")
        let discovery = await ProviderAccountAssembly.makeCodexCards(
            observer: DefaultAccountObserver(
                environment: FakeEnvironment([:]),
                files: FakeFiles(),
                keychain: AccountMissingKeychain(),
                homeDirectory: { home }
            ),
            accountsStore: accounts,
            listDirectories: { _ in [] }
        )

        XCTAssertTrue(discovery.cards.isEmpty)
        XCTAssertEqual(accounts.records.map(\.identityKey), [identity.key])
    }

    private func makeDefaults() throws -> UserDefaults {
        let suite = "OpenUsageTests.CodexCard.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        return defaults
    }
}

private final class RefusingCodexKeychain: KeychainAccessing, @unchecked Sendable {
    func readGenericPassword(service: String) throws -> String? {
        XCTFail("Codex must not read the first item for a service")
        return nil
    }

    func writeGenericPassword(service: String, value: String) throws {
        XCTFail("Codex must not write without an account")
    }

    func readGenericPassword(service: String, account: String) throws -> String? {
        KeychainAccessLedger.shared.noteRefused(KeychainItemRef(service: service, account: account))
        throw KeychainError.accessNeeded(service: service)
    }

    func writeGenericPassword(service: String, account: String, value: String) throws {
        XCTFail("a refused Codex item is not written")
    }
}

private final class AccountMissingKeychain: KeychainAccessing, @unchecked Sendable {
    func readGenericPassword(service: String) throws -> String? { nil }
    func writeGenericPassword(service: String, value: String) throws {}
    func readGenericPassword(service: String, account: String) throws -> String? { nil }
    func writeGenericPassword(service: String, account: String, value: String) throws {}
}
