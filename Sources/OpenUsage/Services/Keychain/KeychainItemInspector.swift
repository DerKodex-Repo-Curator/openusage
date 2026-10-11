import Foundation
import Security
import Synchronization

enum KeychainAccountSelector: Hashable, Sendable {
    case named(String)
    case any
}

struct KeychainItemAccess: Equatable, Sendable {
    var account: String
    var securityReadsSilently: Bool
    /// The partition list's first entry is `apple-tool:`, so the last secret writer was `security`.
    var lastWriterIsSecurityTool: Bool
}

enum KeychainInspection: Equatable, Sendable {
    case notFound
    case locked
    case found(KeychainItemAccess)
    case failed(OSStatus)
}

enum KeychainQuietRead: Equatable, Sendable {
    case value(Data)
    case notFound
    case refused(OSStatus)
    case failed(OSStatus)
}

enum KeychainQuietUpdate: Equatable, Sendable {
    case updated
    case notFound
    case refused(OSStatus)
    case failed(OSStatus)
}

protocol KeychainItemInspecting: Sendable {
    func inspect(service: String, account: KeychainAccountSelector) -> KeychainInspection
    func readQuietly(service: String, account: KeychainAccountSelector) -> KeychainQuietRead
    func updateQuietly(service: String, account: String, data: Data) -> KeychainQuietUpdate
}

enum KeychainACLDecision {
    struct DecryptEntry: Equatable, Sendable {
        var trustedApplicationPaths: [String]?
        var requiresPassphrase: Bool
    }

    static func securityReadsSilently(decrypt: [DecryptEntry], partitions: [String]?) -> Bool {
        guard let partitions, partitions.contains("apple-tool:") else { return false }
        return decrypt.contains { entry in
            guard !entry.requiresPassphrase else { return false }
            guard let paths = entry.trustedApplicationPaths else { return true }
            return paths.contains("/usr/bin/security")
        }
    }

    static func lastWriterIsSecurityTool(partitions: [String]?) -> Bool {
        partitions?.first == "apple-tool:"
    }
}

enum KeychainPartitionList {
    static func parse(hexDescription: String) -> [String]? {
        guard let data = Data(hexEncoded: hexDescription),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let partitions = plist["Partitions"] as? [String]
        else { return nil }
        return partitions
    }
}

extension Data {
    fileprivate init?(hexEncoded hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}

/// Process-wide Keychain UI switch. Legacy items ignore per-query "no UI" flags, so this is the only
/// switch that stops a background read from showing a dialog. It is never turned back on.
public enum KeychainUserInteraction {
    private static let disabled = Mutex(false)

    /// Call once at launch, before any Keychain access.
    public static func disableForProcess() {
        let status = SecKeychainSetUserInteractionAllowed(false)
        guard status == errSecSuccess else {
            AppLog.error(.keychain, "failed to disable Keychain UI (\(status))")
            return
        }
        disabled.withLock { $0 = true }
        AppLog.info(.keychain, "keychain UI disabled for this process")
    }

    static var isDisabledForProcess: Bool {
        disabled.withLock { $0 }
    }
}
