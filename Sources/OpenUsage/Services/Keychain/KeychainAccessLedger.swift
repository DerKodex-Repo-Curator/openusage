import Foundation
import Synchronization

struct KeychainItemRef: Hashable, Sendable {
    let service: String
    let account: String
}

final class KeychainAccessLedger: Sendable {
    static let shared = KeychainAccessLedger()

    private struct State {
        var order: [KeychainItemRef] = []
    }

    private let state = Mutex(State())

    func noteRefused(_ item: KeychainItemRef) {
        let inserted = state.withLock { state -> Bool in
            guard !state.order.contains(item) else { return false }
            state.order.append(item)
            return true
        }
        guard inserted else { return }
        AppLog.warn(.keychain, "keychain access refused service=\(item.service) account=\(item.account)")
    }

    func noteReadable(_ item: KeychainItemRef) {
        guard remove(item) else { return }
        AppLog.info(.keychain, "keychain item readable service=\(item.service) account=\(item.account)")
    }

    func noteMissing(service: String, account: String?) {
        let removed = state.withLock { state -> [KeychainItemRef] in
            let matches = state.order.filter { item in
                item.service == service && (account == nil || item.account == account)
            }
            guard !matches.isEmpty else { return [] }
            state.order.removeAll { item in
                item.service == service && (account == nil || item.account == account)
            }
            return matches
        }
        for item in removed {
            AppLog.info(.keychain, "keychain item missing service=\(item.service) account=\(item.account)")
        }
    }

    func refusedItems(family: String) -> [KeychainItemRef] {
        state.withLock { state in
            state.order.filter { KeychainItemPolicy.forService($0.service).family == family }
        }
    }

    private func remove(_ item: KeychainItemRef) -> Bool {
        state.withLock { state in
            guard let index = state.order.firstIndex(of: item) else { return false }
            state.order.remove(at: index)
            return true
        }
    }
}
