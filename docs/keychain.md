# Keychain access

OpenUsage reads sign-ins that other apps already saved in the login Keychain. A background refresh never opens a Keychain dialog.

## When OpenUsage asks

macOS asks only after you right-click a card and choose **Refresh**. It asks once for each sign-in it could not read quietly. Pick **Always Allow**. That grant sticks, and later refreshes stay silent.

**Allow** (once) lets that single prompt through. The next background refresh still cannot read the item, so the card asks you to Refresh again.

**Deny** closes the dialog and leaves the card as it was. OpenUsage does not ask again until you choose Refresh on that card.

## Why some sign-ins never ask

Claude Code, GitHub CLI, Cursor's command-line token, and Antigravity store their items with the `security` tool. OpenUsage reads and updates those the same way, and only when that read is already silent. If it is not, the card tells you to Refresh and choose Always Allow. OpenUsage does not create a replacement item for another app's sign-in.

Claude Desktop's safe storage, Claude Swap's vault, and Codex's Keychain login are written by those apps themselves. OpenUsage reads them after you allow it.

## Codex's Keychain login

When Codex's Keychain token is about to expire, OpenUsage renews it and saves it back. macOS then asks Codex once for access to its own login. When Codex renews the token itself, the card asks you to Refresh and choose **Always Allow** again. A Codex login in `auth.json` never involves the Keychain.
