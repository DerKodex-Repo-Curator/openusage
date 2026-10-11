import Foundation

protocol KeychainAccessing: Sendable {
    func readGenericPassword(service: String) throws -> String?
    func writeGenericPassword(service: String, value: String) throws
    func readGenericPasswordForCurrentUser(service: String) throws -> String?
    func writeGenericPasswordForCurrentUser(service: String, value: String) throws
    func readGenericPassword(service: String, account: String) throws -> String?
    /// Update the item belonging to this exact account, without changing another account's login.
    func writeGenericPassword(service: String, account: String, value: String) throws
    func canWriteWithSecurityTool(service: String) -> Bool
    func canWriteWithSecurityToolForCurrentUser(service: String) -> Bool
    /// Nil means the check itself failed, so each caller picks its own safe side.
    func genericPasswordExists(service: String) -> Bool?
}

extension KeychainAccessing {
    func readGenericPasswordForCurrentUser(service: String) throws -> String? {
        try readGenericPassword(service: service)
    }

    func writeGenericPasswordForCurrentUser(service: String, value: String) throws {
        try writeGenericPassword(service: service, value: value)
    }

    func readGenericPassword(service: String, account: String) throws -> String? {
        try readGenericPassword(service: service)
    }

    /// An accessor without scoped-write support must fail rather than drop the account and risk
    /// overwriting a different login.
    func writeGenericPassword(service: String, account: String, value: String) throws {
        throw KeychainError.writeFailed("Account-scoped Keychain writes are unavailable.")
    }

    func canWriteWithSecurityTool(service: String) -> Bool {
        true
    }

    func canWriteWithSecurityToolForCurrentUser(service: String) -> Bool {
        true
    }

    func genericPasswordExists(service: String) -> Bool? {
        do {
            return try readGenericPassword(service: service) != nil
        } catch {
            return nil
        }
    }
}

enum KeychainError: Error, LocalizedError, Equatable {
    case readFailed(String)
    case writeFailed(String)
    case accessNeeded(service: String)
    case locked

    var errorDescription: String? {
        switch self {
        case .readFailed(let message):
            return message.isEmpty ? "Keychain read failed." : message
        case .writeFailed(let message):
            return message.isEmpty ? "Keychain write failed." : message
        case .accessNeeded:
            return "OpenUsage needs your OK to read this sign-in. Right-click the card, choose Refresh, then click Always Allow."
        case .locked:
            return "Your login Keychain is locked. Unlock it, then refresh."
        }
    }
}
