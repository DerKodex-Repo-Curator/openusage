import Foundation
import Synchronization

struct KeychainItemPolicy: Equatable, Sendable {
    enum Writer: Equatable, Sendable {
        case securityTool
        case ownerApp
    }

    let writer: Writer
    let family: String?

    static func forService(_ service: String) -> KeychainItemPolicy {
        if service.hasPrefix(ClaudeAuthStore.keychainServicePrefix) {
            return KeychainItemPolicy(writer: .securityTool, family: "claude")
        }
        if service == CopilotAuthStore.ghKeychainService {
            return KeychainItemPolicy(writer: .securityTool, family: "copilot")
        }
        if service == CursorAuthStore.keychainAccessTokenService
            || service == CursorAuthStore.keychainRefreshTokenService {
            return KeychainItemPolicy(writer: .securityTool, family: "cursor")
        }
        if service == AntigravityAuthStore.keychainService {
            return KeychainItemPolicy(writer: .securityTool, family: "antigravity")
        }
        if service.hasSuffix(".icloud-sync-device-id.v1") {
            return KeychainItemPolicy(writer: .securityTool, family: nil)
        }
        if service == ClaudeDesktopSafeStorageKeyReader.service {
            return KeychainItemPolicy(writer: .ownerApp, family: "claude")
        }
        if service == ClaudeSwapAccount.keychainService {
            return KeychainItemPolicy(writer: .ownerApp, family: "claude")
        }
        if service == CodexAuthStore.keychainService {
            return KeychainItemPolicy(writer: .ownerApp, family: "codex")
        }
        warnOnce(service)
        return KeychainItemPolicy(writer: .ownerApp, family: nil)
    }

    private static let warnedServices = Mutex<Set<String>>([])

    private static func warnOnce(_ service: String) {
        let inserted = warnedServices.withLock { warned -> Bool in
            warned.insert(service).inserted
        }
        guard inserted else { return }
        AppLog.warn(.keychain, "unknown keychain service '\(service)'; treating it as owned by another app")
    }
}
