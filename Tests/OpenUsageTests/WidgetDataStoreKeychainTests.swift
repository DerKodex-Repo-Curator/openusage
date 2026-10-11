import XCTest
@testable import OpenUsage

@MainActor
final class WidgetDataStoreKeychainTests: XCTestCase {
    func testRefreshFromUserRequestsEachRefusedItemThenRefreshes() async {
        let ledger = KeychainAccessLedger()
        let first = KeychainItemRef(service: "Claude Code-credentials", account: "rebers")
        let second = KeychainItemRef(service: ClaudeDesktopSafeStorageKeyReader.service, account: "Claude Key")
        ledger.noteRefused(first)
        ledger.noteRefused(second)
        let requester = RecordingRequester()
        let runtime = CountingProviderRuntime(
            provider: provider,
            descriptors: [],
            snapshot: ProviderSnapshot.make(provider: provider, plan: nil, lines: [], refreshedAt: Date())
        )
        let store = makeStore(runtime: runtime, requester: requester, ledger: ledger)

        await store.refreshFromUser(providerID: provider.id)

        XCTAssertEqual(requester.items, [first, second])
        XCTAssertEqual(runtime.refreshCount, 1)
    }

    func testRefreshFromUserSkipsTheRequesterWhenNothingIsRefused() async {
        let requester = RecordingRequester()
        let runtime = CountingProviderRuntime(
            provider: provider,
            descriptors: [],
            snapshot: ProviderSnapshot.make(provider: provider, plan: nil, lines: [], refreshedAt: Date())
        )
        let store = makeStore(runtime: runtime, requester: requester, ledger: KeychainAccessLedger())

        await store.refreshFromUser(providerID: provider.id)

        XCTAssertTrue(requester.items.isEmpty)
        XCTAssertEqual(runtime.refreshCount, 1)
    }

    func testBackgroundRefreshNeverRequests() async {
        let ledger = KeychainAccessLedger()
        ledger.noteRefused(KeychainItemRef(service: CodexAuthStore.keychainService, account: "cli|abc"))
        let requester = RecordingRequester()
        let runtime = CountingProviderRuntime(
            provider: Provider(id: "codex", displayName: "Codex", icon: .providerMark("codex")),
            descriptors: [],
            snapshot: ProviderSnapshot.make(
                provider: Provider(id: "codex", displayName: "Codex", icon: .providerMark("codex")),
                plan: nil, lines: [], refreshedAt: Date()
            )
        )
        let store = makeStore(runtime: runtime, requester: requester, ledger: ledger)

        _ = await store.refresh(providerID: "codex", force: true)

        XCTAssertTrue(requester.items.isEmpty)
        XCTAssertEqual(runtime.refreshCount, 1)
    }

    func testSecondClickDuringAGrantDoesNotAskAgain() async {
        let ledger = KeychainAccessLedger()
        ledger.noteRefused(KeychainItemRef(service: "Claude Code-credentials", account: "rebers"))
        let requester = GateRequester(ledger: ledger)
        let entered = expectation(description: "grant started")
        entered.assertForOverFulfill = false
        requester.onEnter = { entered.fulfill() }
        let runtime = CountingProviderRuntime(
            provider: provider,
            descriptors: [],
            snapshot: ProviderSnapshot.make(provider: provider, plan: nil, lines: [], refreshedAt: Date())
        )
        let store = makeStore(runtimes: [runtime], requester: requester, ledger: ledger)

        let first = Task { await store.refreshFromUser(providerID: provider.id) }
        await fulfillment(of: [entered], timeout: 2)
        let second = Task { await store.refreshFromUser(providerID: provider.id) }
        await Task.yield()
        requester.release()
        await first.value
        await second.value

        XCTAssertEqual(requester.count, 1)
        XCTAssertEqual(runtime.refreshCount, 1)
    }

    func testAccountCardsInOneFamilyShareOneGrant() async {
        let ledger = KeychainAccessLedger()
        ledger.noteRefused(KeychainItemRef(service: "Claude Code-credentials", account: "rebers"))
        let requester = GateRequester(ledger: ledger)
        let entered = expectation(description: "grant started")
        entered.assertForOverFulfill = false
        requester.onEnter = { entered.fulfill() }
        let work = Provider(
            id: ProviderAccountID.make(family: "claude", identityKey: "work|me@example.com"),
            displayName: "Claude",
            icon: .providerMark("claude")
        )
        let personalRuntime = CountingProviderRuntime(
            provider: provider,
            descriptors: [],
            snapshot: ProviderSnapshot.make(provider: provider, plan: nil, lines: [], refreshedAt: Date())
        )
        let workRuntime = CountingProviderRuntime(
            provider: work,
            descriptors: [],
            snapshot: ProviderSnapshot.make(provider: work, plan: nil, lines: [], refreshedAt: Date())
        )
        let store = makeStore(runtimes: [personalRuntime, workRuntime], requester: requester, ledger: ledger)

        let first = Task { await store.refreshFromUser(providerID: provider.id) }
        await fulfillment(of: [entered], timeout: 2)
        let second = Task { await store.refreshFromUser(providerID: work.id) }
        await Task.yield()
        requester.release()
        await first.value
        await second.value

        XCTAssertEqual(requester.count, 1)
        XCTAssertEqual(personalRuntime.refreshCount, 1)
        XCTAssertEqual(workRuntime.refreshCount, 1)
    }

    func testNoticeAppearsOnlyForListedCategoriesWithRefusedItems() async {
        let ledger = KeychainAccessLedger()
        let cases: [(Error, Bool)] = [
            (ClaudeAuthError.notLoggedIn, true),
            (ClaudeAuthError.desktopPermissionRequired, true),
            (ClaudeAuthError.invalidOAuthURL("nope"), true),
            (ClaudeAuthError.tokenExpired, false),
        ]
        for (error, shows) in cases {
            let runtime = TestProviderRuntime(
                provider: provider,
                descriptors: [],
                snapshot: ProviderSnapshot.error(provider: provider, error: error)
            )
            let store = makeStore(runtime: runtime, requester: nil, ledger: ledger)
            _ = await store.refresh(providerID: provider.id, force: true)
            ledger.noteRefused(KeychainItemRef(service: "Claude Code-credentials", account: "rebers"))
            if shows {
                XCTAssertEqual(
                    store.headerNotice(for: provider.id),
                    "OpenUsage needs your OK to read your Claude sign-in. Right-click Claude, choose Refresh Claude, then click Always Allow."
                )
            } else {
                XCTAssertEqual(store.headerNotice(for: provider.id), error.localizedDescription)
            }
            ledger.noteReadable(KeychainItemRef(service: "Claude Code-credentials", account: "rebers"))
            XCTAssertEqual(store.headerNotice(for: provider.id), error.localizedDescription)
        }
    }

    private let provider = Provider(id: "claude", displayName: "Claude", icon: .providerMark("claude"))

    private func makeStore(
        runtime: ProviderRuntime,
        requester: (any KeychainAccessRequesting)?,
        ledger: KeychainAccessLedger
    ) -> WidgetDataStore {
        makeStore(runtimes: [runtime], requester: requester, ledger: ledger)
    }

    private func makeStore(
        runtimes: [ProviderRuntime],
        requester: (any KeychainAccessRequesting)?,
        ledger: KeychainAccessLedger
    ) -> WidgetDataStore {
        let suite = "OpenUsageTests.KeychainStore.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        let registry = WidgetRegistry(providers: runtimes.map(\.provider), descriptors: [])
        return WidgetDataStore(
            registry: registry,
            providers: runtimes,
            defaults: defaults,
            keychainAccessRequester: requester,
            keychainLedger: ledger
        )
    }
}

private final class RecordingRequester: KeychainAccessRequesting, @unchecked Sendable {
    var items: [KeychainItemRef] = []

    func request(_ item: KeychainItemRef) async -> KeychainGrant {
        items.append(item)
        return .granted
    }
}

private final class GateRequester: KeychainAccessRequesting, @unchecked Sendable {
    let ledger: KeychainAccessLedger
    var onEnter: () -> Void = {}
    private(set) var count = 0
    private var holds: [CheckedContinuation<Void, Never>] = []

    init(ledger: KeychainAccessLedger) { self.ledger = ledger }

    func request(_ item: KeychainItemRef) async -> KeychainGrant {
        count += 1
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            holds.append(cont)
            onEnter()
        }
        ledger.noteReadable(item)
        return .granted
    }

    func release() {
        holds.forEach { $0.resume() }
        holds = []
    }
}
