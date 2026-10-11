import Foundation

extension WidgetDataStore {
    func refreshFromUser(providerID: String) async {
        await requestKeychainAccess(family: ProviderAccountID.family(of: providerID))
        await refresh(providerID: providerID, force: true)
    }

    /// Refused items are tracked per family, so all of a family's account cards share one grant.
    private func requestKeychainAccess(family: String) async {
        if let running = keychainGrants[family] {
            return await running.value
        }
        let refused = keychainLedger.refusedItems(family: family)
        guard let requester = keychainAccessRequester, !refused.isEmpty else { return }
        let grant = Task {
            for item in refused {
                _ = await requester.request(item)
            }
        }
        keychainGrants[family] = grant
        await grant.value
        keychainGrants[family] = nil
    }

    func keychainAccessNotice(for providerID: String) -> String? {
        let family = ProviderAccountID.family(of: providerID)
        guard !keychainLedger.refusedItems(family: family).isEmpty else { return nil }
        switch providerErrorCategories[providerID] {
        case .notLoggedIn, .credentialAccess, .authInvalid:
            break
        default:
            return nil
        }
        let card = providersByID[providerID]?.provider.displayName ?? providerID
        let familyName = familyDisplayName(family: family, cardName: card)
        return "OpenUsage needs your OK to read your \(familyName) sign-in. Right-click \(card), choose Refresh \(card), then click Always Allow."
    }

    private func familyDisplayName(family: String, cardName: String) -> String {
        if let exact = providersByID[family]?.provider.displayName { return exact }
        if let separator = cardName.range(of: " — ") ?? cardName.range(of: ": ") {
            return String(cardName[..<separator.lowerBound])
        }
        return cardName
    }
}
