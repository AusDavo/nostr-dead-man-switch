# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.5] — 2026-07-03

### Added

- **Webhook HMAC signing.** The `webhook` action accepts an optional
  `secret` field. When set, every request carries an
  `X-Deadman-Signature: sha256=<hex of HMAC-SHA256(secret, body)>`
  header (GitHub's webhook convention) so receivers — n8n, Home
  Assistant, custom APIs — can verify a request genuinely came from
  this switch and reject spoofed payloads. Absent `secret` leaves
  requests unsigned, exactly as before. The README documents
  receiver-side verification with a constant-time comparison example.
  (#29, #44)

## [0.2.4] — 2026-06-02

Visual release. Completes the light "document" rebrand across the
authenticated admin pages. No behavior, config, or API changes.

### Changed

- **Admin pages now match the document design.** The watcher setup,
  generated-key, configuration, and roster pages move off the legacy
  palette shim onto the document system: oxblood accent, monospace
  section labels, and hairline rules in place of rounded cards — the same
  vocabulary as the status page and public surfaces.
- The configuration editor's field grid collapses to a single column on
  phone-width screens; it previously overflowed the viewport.

### Removed

- Retired the now-unused legacy CSS token aliases (`--bg`, `--card`,
  `--accent`, `--border`, `--text`, `--muted`, `--accent-ink`) from the
  shared stylesheet. Only the paper/ink/oxblood and semantic-state tokens
  remain.

## [0.2.3] — 2026-06-01

Visual release. The web UI is rebranded from a dark dashboard to a light
"document" aesthetic. No behavior, config, or API changes.

### Changed

- **New look across every page.** The status page, admin hub, login,
  roster, config editor, watcher setup, and signup pages move from the
  dark amber-on-graphite theme to a light certificate/statement design:
  near-neutral paper, near-black ink, an oxblood accent, serif display
  figures, and monospace for npubs, relays, timers, and other protocol
  values. Status now reads as a stamp (the triggered state is a red stamp
  on the sheet).
- Layout uses hairline rules and dotted-leader rows in place of cards.
- Replaced the side-stripe alert blocks with full borders. The roster
  reads as a register, and its tables scroll horizontally on narrow
  screens rather than breaking the layout.
- Timer figures collapse to a single column on phone-width screens.

### Accessibility

- All text meets WCAG AA contrast (body around 6.6:1, status colors at or
  above 5.3:1), and status is conveyed by a labeled stamp, not color
  alone.

[0.2.3]: https://github.com/AusDavo/nostr-dead-man-switch/releases/tag/v0.2.3

## [0.2.2] — 2026-05-31

Patch release. Fixes for the v0.2 invite flow.

### Fixed

- **Invite links now work for logged-out recipients.** Visiting
  `/admin/signup?code=…` while signed out bounced to `/login` and dropped
  the `code` on the way, so after signing in the visitor landed on the
  closed page and the code was never redeemed. The login flow now
  preserves the original destination through the round-trip (a sanitized,
  same-origin `next` — open-redirect targets are rejected), so the code
  survives sign-in.

### Admin roster

- Dropped the misleading "shown once" note on a freshly minted code —
  invite codes are listed in the roster, not one-time secrets. Every
  available code in the list now has its own **Copy link** button.

[0.2.2]: https://github.com/AusDavo/nostr-dead-man-switch/releases/tag/v0.2.2

## [0.2.1] — 2026-05-31

Patch release. Roster UX polish on top of v0.2.0.

### Admin roster

- Minting an invite code now shows a full, one-click-copyable signup
  link (`https://<host>/admin/signup?code=…`) with a **Copy link**
  button, instead of just the bare code and a relative path. The link is
  built from the request, so it resolves to the correct public hostname
  behind a TLS-terminating reverse proxy (honors `X-Forwarded-Proto`).

[0.2.1]: https://github.com/AusDavo/nostr-dead-man-switch/releases/tag/v0.2.1

## [0.2.0] — 2026-05-31

Minor release. The v0.2 "operator onramp" milestone: federation enrollment
is now terminal-free, the precondition for one-click Umbrel/Start9 packaging.

### Federation enrollment (whitelist gating v1)

- `admin_npub` config field: its holder is auto-enrolled as `plan=admin`
  and gets a roster management UI at `/admin/roster` — see enrolled users
  (plan, added-at, running, last-seen), grant/revoke access, and
  mint/revoke invite codes, all from the browser.
- Invite codes: the admin mints single-use codes and shares
  `/admin/signup?code=…`. A friend redeems one in-browser and self-enrolls
  as `plan=invite`, then bootstraps their watcher key — no shell access
  needed. Configure static boot codes with `invite_codes`, or mint at
  runtime from the roster (or `--generate-invite`).
- Friendly closed page: an npub that arrives without a valid code sees an
  "invite-only host" page showing their npub to share with the operator,
  instead of a raw 401.
- New CLI flags: `--grant-free npub1…` (admit as `plan=free`) and
  `--generate-invite` (mint a code). `--whitelist-list` now shows a
  `plan=` column.
- Revocation goes through the same teardown path a future expiry sweep
  will use — `registry.Stop → store.DeleteUser → whitelist.Remove` — and
  never fires trigger actions, enforced by a regression test.

### Compatibility

- A pre-plan `whitelist.json` (version 1) loads unchanged; existing
  entries are grandfathered (`plan_kind` empty) and never auto-modified.
  The file is rewritten at version 2 on the next mutation.
- Zero-config upgrade (no `admin_npub`, no `invite_codes`) behaves exactly
  as before: a closed, CLI-enrolled host — the only visible change is the
  friendly closed page replacing the old hard 401.

[0.2.0]: https://github.com/AusDavo/nostr-dead-man-switch/releases/tag/v0.2.0

## [0.1.1] — 2026-05-15

Patch release. One operator-facing feature plus a small polish pass.

### Admin dashboard

- Re-arm a triggered switch from `/admin` without shell access. The
  Triggered card now has a CSRF-protected "Re-arm switch" button (with
  a confirm prompt) that clears the triggered state, advances
  `last_seen` to now, and restarts the watcher goroutine so monitoring
  resumes. Self-hosted Umbrel / Start9 operators no longer need
  filesystem access to recover from an accidental trigger.
- Button labels on the watcher-setup and config editor pages now use
  action-specific verbs (`Generate bot key`, `Import nsec`, `Test fire`)
  instead of generic ones (`Generate`, `Import`, `Test`).

### Docs

- README quick-start reorders the bootstrap steps so `.env` exists
  before the first `docker compose run` invocation (which needs it).
  Thanks to @brendio for the report (#18).

[0.1.1]: https://github.com/AusDavo/nostr-dead-man-switch/releases/tag/v0.1.1

## [0.1.0] — 2026-05-13

First tagged release. Pre-1.0: the config schema, CLI flags, and
on-disk state file format may still change before 1.0, but on-disk
files now carry a `schema_version` field so future shape changes have
a migration path.

### Watcher (silence detection)

- Nostr-native silence detection: any signed event on the configured
  relays for the subject npub resets the timer.
- Configurable silence threshold, warning interval, and warning count.
- Manual check-in fallback for when relays are unreachable.
- Configuration warnings surfaced on the dashboard for placeholders,
  example addresses, and missing core fields.
- Per-relay connection status visible on the status page.

### Actions (triggered on silence)

- `email` (SMTP), `webhook`, `nostr_note` (public note), and `nostr_dm`
  (NIP-04 encrypted DM to a specific npub).
- Action templates seeded in `/admin/config` with sensible defaults.
- Per-action "Test" button in the admin UI to dry-run delivery without
  triggering the switch.

### Federation v1 (multi-tenant)

- Per-user `UserWatcher`s supervised by a `Registry`, each with its
  own subject npub, watcher keypair, and action set.
- Per-tenant on-disk layout under `<state_dir>/users/<npub>/` with
  `config.json`, `state.json`, and `watcher.nsec.enc`.
- Sealed nsec at-rest encryption via a `Sealer` derived from the host
  secret.
- Self-DM config propagation (NIP-44): users edit config in the admin
  UI; the watcher publishes the new config to itself over Nostr, and
  on next boot the watcher hydrates from the most recent self-DM.
- Whitelist of permitted subject npubs with CLI helpers
  (`--whitelist-add/-remove/-list`).
- Legacy single-switch deployments are imported into the per-user
  layout on first boot of a federation binary.

### Admin dashboard

- Public `/` status page (aggregate, no per-tenant detail leaked).
- Nostr (NIP-07) sign-in: holders of a whitelisted npub can sign a
  fresh challenge to access `/admin`.
- `/admin` hub linking out to per-tenant config, watcher setup, and
  the reveal-nsec flow.
- `/admin/config` field-based form (replaces the earlier JSON
  textarea) with number+unit duration pickers and seeded defaults.
- `/admin/watcher` provisioning: generate a fresh watcher keypair or
  import an existing nsec.
- Reveal-watcher-nsec flow gated by a fresh NIP-07 signature.
- Boot-time watcher start failures surfaced on `/admin/watcher`.

### Operations

- `/health` JSON endpoint reports mode (legacy or federation), watcher
  count, version, and (in legacy mode) silence/warning state.
- `--version` flag prints the embedded build tag.
- `schema_version` field on `state.json` and `config.json` with a
  forward-version lockout: a binary refuses to load files claiming a
  schema version newer than it supports. Legacy unversioned files are
  migrated on load and rewritten to disk.
- GitHub Actions CI runs `go vet` and `go test` on push and PR.
- Release workflow builds multi-arch (`linux/amd64`, `linux/arm64`)
  images and publishes to `ghcr.io/ausdavo/nostr-dead-man-switch` on
  `v*.*.*` tag pushes. arm64 is included so Umbrel / Start9 home
  nodes can pull directly.

[0.1.0]: https://github.com/AusDavo/nostr-dead-man-switch/releases/tag/v0.1.0
