import Foundation
import Security

enum KeychainGrant: Equatable, Sendable {
    case granted
    case allowedOnce
    case denied
    case notFound
    case failed(String)
}

protocol KeychainAccessRequesting: Sendable {
    func request(_ item: KeychainItemRef) async -> KeychainGrant
}

struct KeychainAccessRequester: KeychainAccessRequesting {
    var processRunner: any ProcessRunning
    var accessor: SecurityKeychainAccessor
    var appExecutablePath: String

    static func live() -> KeychainAccessRequester {
        precondition(
            NSClassFromString("XCTestCase") == nil,
            "the live Keychain requester must not run under XCTest"
        )
        return KeychainAccessRequester(
            processRunner: SystemProcessRunner(),
            accessor: SecurityKeychainAccessor(),
            appExecutablePath: Bundle.main.executablePath ?? ""
        )
    }

    func request(_ item: KeychainItemRef) async -> KeychainGrant {
        let invocation = Self.invocation(
            policy: KeychainItemPolicy.forService(item.service),
            item: item,
            appExecutablePath: appExecutablePath
        )
        let exitCode: Int32? = await Task.detached {
            do {
                // Stdout is the secret for a `security -w` read.
                let result = try self.processRunner.run(
                    executable: invocation.executable,
                    arguments: invocation.arguments,
                    environment: [:],
                    timeout: 600
                )
                return result.exitCode
            } catch {
                return nil
            }
        }.value
        let grant = Self.grant(exitCode: exitCode, read: verify(item))
        AppLog.info(.keychain, "keychain grant \(grant) service=\(item.service) account=\(item.account)")
        return grant
    }

    /// Always Allow trusts the program that asked. The asker must be the program that does the
    /// background reads, which is `security` for items it writes and this app's binary for owner-app
    /// items.
    private static func invocation(
        policy: KeychainItemPolicy,
        item: KeychainItemRef,
        appExecutablePath: String
    ) -> (executable: String, arguments: [String]) {
        switch policy.writer {
        case .securityTool:
            return (
                "/usr/bin/security",
                ["find-generic-password", "-s", item.service, "-a", item.account, "-w"]
            )
        case .ownerApp:
            return (appExecutablePath, [KeychainGrantCommand.flag, item.service, item.account])
        }
    }

    private func verify(_ item: KeychainItemRef) -> Result<String?, Error> {
        Result { try accessor.readGenericPassword(service: item.service, account: item.account) }
    }

    private static func grant(exitCode: Int32?, read: Result<String?, Error>) -> KeychainGrant {
        guard let exitCode else { return .failed("The Keychain prompt did not finish.") }
        switch read {
        case .success(let value) where value != nil:
            return .granted
        case .success:
            return .notFound
        case .failure(let error as KeychainError):
            if case .accessNeeded = error {
                return exitCode == 0 ? .allowedOnce : .denied
            }
            return .failed(error.localizedDescription)
        case .failure(let error):
            return .failed(error.localizedDescription)
        }
    }
}

public enum KeychainGrantCommand {
    public static let flag = "--keychain-grant"

    /// Nil unless `arguments` are exactly `[exe, flag, service, account]`. Otherwise performs one
    /// in-process data read with Keychain UI still at its default, so macOS may ask, and returns an
    /// exit code: 0 read ok, 2 refused or canceled, 3 not found, 4 anything else. Never prints the secret.
    public static func exitCode(for arguments: [String]) -> Int32? {
        guard arguments.count == 4, arguments[1] == flag else { return nil }
        precondition(
            NSClassFromString("XCTestCase") == nil,
            "the Keychain grant read must not run under XCTest"
        )
        let status = copyStatus(service: arguments[2], account: arguments[3])
        switch status {
        case errSecSuccess:
            return 0
        case errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled:
            return 2
        case errSecItemNotFound:
            return 3
        default:
            return 4
        }
    }

    private static func copyStatus(service: String, account: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        result = nil
        return status
    }
}
