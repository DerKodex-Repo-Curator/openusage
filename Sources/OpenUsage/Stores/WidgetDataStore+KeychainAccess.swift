import Foundation

extension WidgetDataStore {
    func refreshFromUser(providerID: String) async {
        let family = ProviderAccountID.family(of: providerID)
        let refused = keychainLedger.refusedItems(family: family)
        if let requester = keychainAccessRequester, !refused.isEmpty {
            guard keychainGrantInFlight.insert(providerID).inserted else { return }
            defer { keychainGrantInFlight.remove(providerID) }
            for item in refused {
                _ = await requester.request(item)
            }
        }
        await refresh(providerID: providerID, force: true)
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
