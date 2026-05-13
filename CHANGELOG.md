# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
