import Foundation
import Security

/// The legacy Security calls are required: partition lists and decrypt ACLs are not on the modern
/// `SecItem` attribute query.
struct SystemKeychainItemInspector: KeychainItemInspecting {
    func inspect(service: String, account: KeychainAccountSelector) -> KeychainInspection {
        precondition(
            NSClassFromString("XCTestCase") == nil,
            "SystemKeychainItemInspector must not run under XCTest"
        )
        switch copyItem(service: service, account: account) {
        case .notFound:
            return .notFound
        case .failed(let status):
            return .failed(status)
        case .item(let attributes, let item):
            if let locked = lockStatus(of: item) { return locked }
            let accountName = attributes[kSecAttrAccount as String] as? String ?? ""
            let flags = accessFlags(of: item)
            return .found(KeychainItemAccess(
                account: accountName,
                securityReadsSilently: flags.securityReadsSilently,
                lastWriterIsSecurityTool: flags.lastWriterIsSecurityTool
            ))
        }
    }

    func readQuietly(service: String, account: KeychainAccountSelector) -> KeychainQuietRead {
        precondition(
            NSClassFromString("XCTestCase") == nil,
            "SystemKeychainItemInspector must not run under XCTest"
        )
        precondition(
            KeychainUserInteraction.isDisabledForProcess,
            "readQuietly requires Keychain UI to be disabled for the process"
        )
        var result: CFTypeRef?
        let status = SecItemCopyMatching(dataQuery(service: service, account: account), &result)
        let data = result as? Data
        result = nil
        return Self.classify(status: status, data: data)
    }

    func updateQuietly(service: String, account: String, data: Data) -> KeychainQuietUpdate {
        precondition(
            NSClassFromString("XCTestCase") == nil,
            "SystemKeychainItemInspector must not run under XCTest"
        )
        precondition(
            KeychainUserInteraction.isDisabledForProcess,
            "updateQuietly requires Keychain UI to be disabled for the process"
        )
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        return Self.classify(updateStatus: status)
    }

    static func classify(status: OSStatus, data: Data?) -> KeychainQuietRead {
        switch status {
        case errSecSuccess:
            guard let data else { return .failed(status) }
            return .value(data)
        case errSecItemNotFound:
            return .notFound
        case errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled:
            return .refused(status)
        default:
            return .failed(status)
        }
    }

    static func classify(updateStatus status: OSStatus) -> KeychainQuietUpdate {
        switch status {
        case errSecSuccess:
            return .updated
        case errSecItemNotFound:
            return .notFound
        case errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled:
            return .refused(status)
        default:
            return .failed(status)
        }
    }

    private enum ItemCopy {
        case notFound
        case failed(OSStatus)
        case item([String: Any], SecKeychainItem)
    }

    private func copyItem(service: String, account: KeychainAccountSelector) -> ItemCopy {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributeQuery(service: service, account: account), &result)
        switch status {
        case errSecItemNotFound:
            return .notFound
        case errSecSuccess:
            guard let attributes = result as? [String: Any],
                  let raw = attributes[kSecValueRef as String]
            else { return .failed(errSecDecode) }
            let cf = raw as CFTypeRef
            guard CFGetTypeID(cf) == SecKeychainItemGetTypeID() else { return .failed(errSecDecode) }
            return .item(attributes, cf as! SecKeychainItem)
        default:
            return .failed(status)
        }
    }

    private func attributeQuery(service: String, account: KeychainAccountSelector) -> CFDictionary {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true,
        ]
        if case .named(let name) = account {
            query[kSecAttrAccount as String] = name
        }
        return query as CFDictionary
    }

    private func dataQuery(service: String, account: KeychainAccountSelector) -> CFDictionary {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
        ]
        if case .named(let name) = account {
            query[kSecAttrAccount as String] = name
        }
        return query as CFDictionary
    }

    private func lockStatus(of item: SecKeychainItem) -> KeychainInspection? {
        var keychain: SecKeychain?
        let copyStatus = SecKeychainItemCopyKeychain(item, &keychain)
        guard copyStatus == errSecSuccess, let keychain else { return .failed(copyStatus) }
        var status: SecKeychainStatus = 0
        let statusResult = SecKeychainGetStatus(keychain, &status)
        guard statusResult == errSecSuccess else { return .failed(statusResult) }
        if status & kSecUnlockStateStatus == 0 { return .locked }
        return nil
    }

    private func accessFlags(of item: SecKeychainItem) -> (securityReadsSilently: Bool, lastWriterIsSecurityTool: Bool) {
        var access: SecAccess?
        guard SecKeychainItemCopyAccess(item, &access) == errSecSuccess, let access else {
            return (false, false)
        }
        let decrypt = decryptEntries(in: access)
        let partitions = partitionList(in: access)
        return (
            KeychainACLDecision.securityReadsSilently(decrypt: decrypt, partitions: partitions),
            KeychainACLDecision.lastWriterIsSecurityTool(partitions: partitions)
        )
    }

    private func decryptEntries(in access: SecAccess) -> [KeychainACLDecision.DecryptEntry] {
        let acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt) as? [SecACL] ?? []
        return acls.compactMap { acl in
            var apps: CFArray?
            var description: CFString?
            var selector = SecKeychainPromptSelector()
            guard SecACLCopyContents(acl, &apps, &description, &selector) == errSecSuccess else { return nil }
            let paths: [String]?
            if let apps = apps as? [SecTrustedApplication] {
                paths = apps.map(trustedPath)
            } else {
                paths = nil
            }
            return KeychainACLDecision.DecryptEntry(
                trustedApplicationPaths: paths,
                requiresPassphrase: selector.contains(.requirePassphase)
            )
        }
    }

    private func partitionList(in access: SecAccess) -> [String]? {
        let acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationPartitionID as CFString) as? [SecACL] ?? []
        guard !acls.isEmpty else { return nil }
        var parsed: [String]?
        for acl in acls {
            var apps: CFArray?
            var description: CFString?
            var selector = SecKeychainPromptSelector()
            guard SecACLCopyContents(acl, &apps, &description, &selector) == errSecSuccess,
                  let hex = description as String?,
                  let partitions = KeychainPartitionList.parse(hexDescription: hex)
            else { return nil }
            if parsed == nil { parsed = partitions }
        }
        return parsed
    }

    private func trustedPath(_ application: SecTrustedApplication) -> String {
        var data: CFData?
        guard SecTrustedApplicationCopyData(application, &data) == errSecSuccess,
              let data = data as Data?
        else { return "" }
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .controlCharacters)
    }
}
