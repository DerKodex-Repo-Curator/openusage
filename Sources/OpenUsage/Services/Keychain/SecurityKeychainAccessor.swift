import Foundation

struct SecurityKeychainAccessor: KeychainAccessing {
    var inspector: any KeychainItemInspecting
    var processRunner: any ProcessRunning
    var ledger: KeychainAccessLedger
    var currentUser: @Sendable () -> String

    init(
        inspector: any KeychainItemInspecting = SystemKeychainItemInspector(),
        processRunner: any ProcessRunning = SystemProcessRunner(),
        ledger: KeychainAccessLedger = .shared,
        currentUser: @escaping @Sendable () -> String = {
            ProcessInfo.processInfo.environment["USER"]?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
                ?? NSUserName()
        }
    ) {
        self.inspector = inspector
        self.processRunner = processRunner
        self.ledger = ledger
        self.currentUser = currentUser
    }

    func readGenericPassword(service: String) throws -> String? {
        try read(service: service, account: .any)
    }

    func readGenericPasswordForCurrentUser(service: String) throws -> String? {
        try read(service: service, account: .named(currentUser()))
    }

    func readGenericPassword(service: String, account: String) throws -> String? {
        try read(service: service, account: .named(account))
    }

    func writeGenericPassword(service: String, value: String) throws {
        try write(service: service, account: nil, value: value)
    }

    func writeGenericPasswordForCurrentUser(service: String, value: String) throws {
        try write(service: service, account: currentUser(), value: value)
    }

    func writeGenericPassword(service: String, account: String, value: String) throws {
        try write(service: service, account: account, value: value)
    }

    func genericPasswordExists(service: String) -> Bool? {
        switch inspector.inspect(service: service, account: .any) {
        case .found:
            return true
        case .notFound:
            ledger.noteMissing(service: service, account: nil)
            return false
        case .locked, .failed:
            return nil
        }
    }

    func canWriteWithSecurityTool(service: String) -> Bool {
        canWriteWithSecurityTool(service: service, account: nil)
    }

    func canWriteWithSecurityToolForCurrentUser(service: String) -> Bool {
        canWriteWithSecurityTool(service: service, account: currentUser())
    }

    private func canWriteWithSecurityTool(service: String, account: String?) -> Bool {
        let policy = KeychainItemPolicy.forService(service)
        guard policy.writer == .securityTool else { return false }
        let selector: KeychainAccountSelector = account.map { .named($0) } ?? .any
        switch inspector.inspect(service: service, account: selector) {
        case .found(let access):
            return access.securityReadsSilently && access.lastWriterIsSecurityTool
        case .notFound:
            return policy.family == nil && account != nil
        case .locked, .failed:
            return false
        }
    }

    private func read(service: String, account selector: KeychainAccountSelector) throws -> String? {
        switch inspector.inspect(service: service, account: selector) {
        case .notFound:
            ledger.noteMissing(service: service, account: namedAccount(selector))
            return nil
        case .locked:
            throw KeychainError.locked
        case .failed(let status):
            AppLog.error(.keychain, "inspect failed for service '\(service)' (\(status))")
            throw KeychainError.readFailed("Could not check the Keychain item for \(service).")
        case .found(let access):
            let policy = KeychainItemPolicy.forService(service)
            let item = KeychainItemRef(service: service, account: access.account)
            switch policy.writer {
            case .securityTool:
                return try readWithSecurity(service: service, item: item, access: access)
            case .ownerApp:
                return try readFromOwner(service: service, item: item)
            }
        }
    }

    private func readWithSecurity(service: String, item: KeychainItemRef, access: KeychainItemAccess) throws -> String? {
        guard access.securityReadsSilently else {
            ledger.noteRefused(item)
            throw KeychainError.accessNeeded(service: service)
        }
        let outcome = runSecurity(
            ["find-generic-password", "-s", service, "-a", access.account, "-w"],
            timeout: 10,
            service: service
        )
        switch outcome {
        case .timedOut:
            throw KeychainError.readFailed("Keychain request for \(service) did not finish.")
        case .finished(let result):
            switch result.exitCode {
            case 0:
                ledger.noteReadable(item)
                return secret(from: result.stdout)
            case 44:
                ledger.noteMissing(service: service, account: access.account)
                return nil
            default:
                AppLog.error(.keychain, "security read failed for service '\(service)' (exit \(result.exitCode))")
                throw KeychainError.readFailed("Could not read the Keychain item for \(service).")
            }
        }
    }

    private func readFromOwner(service: String, item: KeychainItemRef) throws -> String? {
        switch inspector.readQuietly(service: service, account: .named(item.account)) {
        case .value(let data):
            guard let text = String(data: data, encoding: .utf8) else {
                throw KeychainError.readFailed("Keychain item for \(service) is not valid UTF-8.")
            }
            ledger.noteReadable(item)
            return text.isEmpty ? nil : text
        case .notFound:
            ledger.noteMissing(service: service, account: item.account)
            return nil
        case .refused:
            ledger.noteRefused(item)
            throw KeychainError.accessNeeded(service: service)
        case .failed(let status):
            AppLog.error(.keychain, "quiet read failed for service '\(service)' (\(status))")
            throw KeychainError.readFailed("Could not read the Keychain item for \(service).")
        }
    }

    private func write(service: String, account explicit: String?, value: String) throws {
        let policy = KeychainItemPolicy.forService(service)
        let selector: KeychainAccountSelector = explicit.map { .named($0) } ?? .any
        switch inspector.inspect(service: service, account: selector) {
        case .locked:
            throw KeychainError.locked
        case .failed(let status):
            AppLog.error(.keychain, "inspect failed for service '\(service)' (\(status))")
            throw KeychainError.writeFailed("Could not check the Keychain item for \(service).")
        case .notFound:
            guard policy.writer == .securityTool, policy.family == nil, let explicit else {
                throw KeychainError.writeFailed("not recreating another app's sign-in")
            }
            try addPassword(service: service, account: explicit, value: value, update: false)
        case .found(let access):
            let item = KeychainItemRef(service: service, account: access.account)
            switch policy.writer {
            case .securityTool:
                guard access.securityReadsSilently, access.lastWriterIsSecurityTool else {
                    ledger.noteRefused(item)
                    throw KeychainError.accessNeeded(service: service)
                }
                try addPassword(service: service, account: access.account, value: value, update: true)
            case .ownerApp:
                try updateInProcess(service: service, item: item, value: value)
            }
        }
    }

    /// macOS then lets only OpenUsage read the item silently, so the owner app asks its user once on
    /// its next read.
    private func updateInProcess(service: String, item: KeychainItemRef, value: String) throws {
        switch inspector.updateQuietly(service: service, account: item.account, data: Data(value.utf8)) {
        case .updated:
            ledger.noteReadable(item)
        case .notFound:
            ledger.noteMissing(service: service, account: item.account)
            throw KeychainError.writeFailed("not recreating another app's sign-in")
        case .refused:
            ledger.noteRefused(item)
            throw KeychainError.accessNeeded(service: service)
        case .failed(let status):
            AppLog.error(.keychain, "quiet update failed for service '\(service)' (\(status))")
            throw KeychainError.writeFailed("Could not update the Keychain item for \(service).")
        }
    }

    private func addPassword(service: String, account: String, value: String, update: Bool) throws {
        var arguments = ["add-generic-password"]
        if update { arguments.append("-U") }
        arguments += ["-s", service, "-a", account, "-X", hex(value)]
        switch runSecurity(arguments, timeout: 10, service: service) {
        case .timedOut:
            throw KeychainError.writeFailed("Keychain update for \(service) did not finish.")
        case .finished(let result):
            guard result.exitCode == 0 else {
                AppLog.error(.keychain, "security write failed for service '\(service)' (exit \(result.exitCode))")
                throw KeychainError.writeFailed("Could not update the Keychain item for \(service).")
            }
        }
    }

    private enum SecurityOutcome {
        case finished(ProcessResult)
        case timedOut
    }

    private func runSecurity(_ arguments: [String], timeout: TimeInterval, service: String) -> SecurityOutcome {
        do {
            let result = try processRunner.run(
                executable: "/usr/bin/security",
                arguments: arguments,
                environment: [:],
                timeout: timeout
            )
            return .finished(result)
        } catch is ProcessRunnerError {
            AppLog.error(
                .keychain,
                "silent preflight was wrong for service '\(service)'; a Keychain dialog may have appeared"
            )
            return .timedOut
        } catch {
            AppLog.error(.keychain, "could not run security for service '\(service)': \(error.localizedDescription)")
            return .timedOut
        }
    }

    /// `security -w` appends one newline.
    private func secret(from stdout: String) -> String? {
        var text = stdout
        if text.hasSuffix("\n") { text.removeLast() }
        return text.isEmpty ? nil : text
    }

    private func hex(_ value: String) -> String {
        Data(value.utf8).map { String(format: "%02x", $0) }.joined()
    }

    private func namedAccount(_ selector: KeychainAccountSelector) -> String? {
        if case .named(let account) = selector { return account }
        return nil
    }
}
