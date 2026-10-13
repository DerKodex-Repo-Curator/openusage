# Plan: Bring Runway's Speed Work to OpenUsage

Status: plan for review. Nothing is built yet.
Baseline: OpenUsage `main` @ `66aada23` (2026-10-13). Source fork: [mstallone/runway](https://github.com/mstallone/runway) @ `d017e2fe`.

## Why

Runway forked OpenUsage at `9d2bf09` (2026-07-19) and rebuilt the hot paths. Its own measurements against that fork point (`docs/performance.md` in Runway, one machine, ~27 GB of Codex JSONL plus 400 MB of Claude logs):

| Metric | OpenUsage @ fork point | Runway |
|---|---|---|
| Launch to menu bar icon | 5.4 s | 0.29 s |
| CPU, first 30 s after launch | 21.3 s | 3.8 s |
| First panel open after launch | 2.59 s | 44 ms |
| Warm panel open | 61 ms | 23 ms |
| One refresh pass | 8.6 s | 2.3 s |
| Memory, steady state / peak | 1.09 GB / 2.6 GB | 238 MB / 322 MB |
| Cold first launch: CPU / peak memory | 165 s / 12.9 GB | 12.7 s / 1.7 GB |

Since the fork point, OpenUsage has already shipped some related work, so part of that gap may be gone:
- #1172 bound usage log memory (streamed parsing, oversized-record skip)
- #1136 laggy screen transitions and Settings navigation
- #1111 scrolling update overhead
- #1110 skip status item apply when the strip image is unchanged
- #1338 slow Codex history scans no longer block live quota

**So step 0 is measuring current `main`.** Each PR below has to show a before/after number on the same machine, or we don't ship it.

## What Runway changed, and where we stand today

| Runway PR | Change | Size (src+tests) | OpenUsage today |
|---|---|---|---|
| #45 | Parse only the bytes appended to a JSONL file since the last refresh | +677 / −71 | **Missing.** `Sources/OpenUsage/Providers/IncrementalJSONLScanner.swift:147-154` re-parses the whole file when its size or mtime changed. An active Codex session file is always changing, so every refresh re-reads it from the start (Runway measured 8.8 s CPU per batch for a heavy Codex user). |
| #51 | Skip re-aggregation when no log changed; fast day-key computation | +368 / −27 | Probably missing. To check: the provider scanners (`ClaudeLogUsageScanner`, `CodexLogUsageScanner`) re-aggregate all cached items on every refresh even when `toParse` is empty. |
| #48 | Run launch account discovery off the main actor, in parallel per family | +218 / −78 | **Missing, and it gates the menu bar icon.** `OpenUsageApp.swift:96` awaits `AppContainer(...)`, which awaits `ProviderAccountAssembly.make` at `AppContainer.swift:69` (a `@MainActor` struct). The status item is only created after that, at `OpenUsageApp.swift:130`. |
| #47 | Do batch-end work (snapshot cache write, notification check, registry rebuild) once per refresh pass instead of once per provider | +137 / −16 | To check: `WidgetDataStore` batch-end hooks. |
| #57 | Pre-warm the panel off-screen after launch so the first open runs at warm speed | +123 | Missing (no pre-warm anywhere in `Sources/`). |
| #60 | Shared dashboard clock, retained panel height, settle on close: warm open 84 → 35 ms | +176 / −29 | Missing. Partly overlaps #1136. |
| #56 | No per-frame preference churn or spring re-targets during height morphs | +220 / −79 | Partly overlaps #1136 and #1111. Needs a re-measure before porting. |
| #49 | UI render path: cached formatters, memoized menu bar content | +112 / −16 | Partly overlaps #1110. |
| #50 | Small provider and service cleanups | +272 / −43 | Skip unless measurement points at something specific. |
| #54 | Env-gated UI performance harness (`RUNWAY_UI_PROFILE=1`, `script/profile_ui.sh`) | +345 / −4 | Missing. Needed for step 0. |

We can't cherry-pick these: Runway renamed the module (`Sources/Runway/...`) and has drifted. Each item gets re-implemented on our code, using Runway's diff as the reference.

## Proposed PRs, in order

Each PR is independent and roughly 150 to 400 lines. They're ordered by expected payoff for heavy users.

### PR 0: Measure (harness + baseline numbers)
- Add a small env-gated measurement mode (`OPENUSAGE_PERF=1`) that logs:
  - time from launch to status item ready
  - wall time and CPU for each refresh pass
  - first and warm panel open, to first frame (signposts)
  - RSS after launch and at steady state
- Model it on Runway #54, but keep only the signposts and log lines. No scripted UI driver unless the numbers need one.
- Output: a table for current `main` on Robin's machine (real corpus) and on a synthetic corpus (generated multi-GB Codex JSONL) for repeatable runs. This decides whether PRs 3 to 5 are still worth doing.
- ~150 lines.

### PR 1: Append-only JSONL parsing (biggest win for Codex users)
- Extend the per-file `CachedFile` record in `IncrementalJSONLScanner` with:
  - byte offset of the last parsed newline
  - an opaque `Codable` parser state
  - a fingerprint of the last 4 KB before that offset
- When a file only grew (size > cached size, fingerprint still matches), read from the offset, resume the parser with the saved state, and append the new items.
- Anything else (shrunk, fingerprint mismatch, unreadable state, cache version bump) falls back to a full re-parse, as today.
- The Codex parser's session state (model context, token-delta baseline, tier, replay gate) has to become a `Codable` `ParseState`. Claude's parser is per-line and needs little state.
- Edge cases Runway hit in review, which we need tests for:
  - appended bytes with no complete line yet: don't advance the cached size/mtime past unparsed bytes
  - a file truncated and rewritten to the same or larger size: fingerprint catches it
  - a partial final line completed on the next refresh
- Bump the scan cache version so old caches re-parse once.
- Tests: resume equals full parse (property-style, randomly split points), each edge case above.
- ~400 lines including tests.

### PR 2: Skip re-aggregation when nothing changed
- If no file was parsed this pass and the date window didn't change, reuse the previous aggregate.
- Faster day keys: precompute local-midnight boundaries once per pass instead of calling `Calendar` for every item.
- ~200 lines.

### PR 3: Show the menu bar icon before account discovery
- Create the status item with a placeholder or last-cached strip immediately at launch. Build `AppContainer` / `ProviderAccountAssembly` afterwards and hand them to the controller when ready.
- Move the account assembly reads (Keychain, files, shell env) off the main actor and run the Claude and Codex families in parallel. Runway split the work into a `Sendable` readout plus a small main-actor apply step.
- Watch: first-launch and welcome screen ordering (`FirstLaunchWindowController`, `FirstRunSeeder`), and the login-shell environment wait in `ProviderAccountAssembly.make`.
- ~250 lines.

### PR 4: Coalesce batch-end work
- One snapshot cache write, one notification evaluation and one registry rebuild per refresh pass, instead of one per provider.
- ~150 lines.

### PR 5: Faster panel opens (only if PR 0 shows it's still slow)
- Pre-warm: lay out the hosting view off-screen a few seconds after launch (Runway #57, ~120 lines).
- Shared dashboard clock and retained height (Runway #60).
- Skip #56 and #49 unless the PR 0 numbers point at morph or render cost after #1136, #1110 and #1111.

## Open questions
1. Is a synthetic corpus good enough to gate PRs, or should every PR also be measured on Robin's real logs?
2. PR 3 changes what the user sees for the first second: a placeholder icon versus the last cached strip. Which one?
3. Should Runway get credit (PR descriptions or README)? Its code is MIT like ours, but we're re-implementing, not copying.
4. Should PR 1 also cover the Grok and OpenCode scanners that use `IncrementalJSONLScanner`, or start with Codex and Claude only?
