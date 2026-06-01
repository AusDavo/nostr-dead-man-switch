# Product

## Register

product

## Users

Self-hosting Nostr users who run this as a service for themselves and, in federation mode, operators who supervise a roster of enrolled npubs. They are technical: comfortable with relays, npubs/nsecs, Docker, and config files. Their context when using the web UI is occasional and high-stakes — checking switch status, enrolling, adjusting timing/actions, or managing a roster — not daily dwelling. Recipients of warning DMs or triggered payloads may be less technical (a spouse, lawyer, executor), so anything they touch (invite links, public-facing copy) must read plainly.

## Product Purpose

A Nostr-native dead man's switch. It passively monitors a user's npub across relays — any signed event (post, reaction, zap) is proof of life and resets the timer. After a configured silence threshold it sends private warning DMs; if silence continues it triggers configured actions (emails, published notes, webhooks). The web UI is the control surface: status page, login (NIP-07 / nostr auth), enrollment/signup, per-user config, and a federation admin roster. Success is that the operator trusts the switch's state at a glance and never fires it by accident — the irreversibility of triggering is the central design tension.

## Brand Personality

Cypherpunk / terminal. Three words: **sovereign, precise, unflinching.** Voice is direct and technical — it respects the user's competence, names things by their real names (npub, relay, threshold), and does not soften the subject matter with euphemism. Monospace-forward where it carries meaning (keys, addresses, timers, state). Confident and quiet, not loud; the gravity comes from clarity and restraint, not decoration. It should feel like infrastructure you'd trust with something irreversible.

## Anti-references

- **Generic SaaS / Tailwind default**: indigo gradients, rounded cards everywhere, hero-metric template, the "could be any startup" look. Explicitly avoid.
- **Crypto-bro / neon Web3**: glowing gradients, neon purple, hype energy, "to the moon." Explicitly avoid — sovereign tech, not speculation.
- **Enterprise admin console**: dense gray data-grids, bureaucratic chrome, mainframe drabness. The roster and config screens must stay legible and humane, not enterprise-dreary.

## Design Principles

- **State is the product.** The single most important thing on any screen is whether the switch is healthy, warning, or triggered — never make the user hunt for it or doubt it.
- **No accidental triggers.** Irreversible and destructive actions earn friction proportional to their consequence; clarity about what will happen beats speed.
- **Name things truthfully.** Use the real protocol vocabulary (npub, relay, threshold, trigger) and show real values in mono. No dumbing-down for users who chose to self-host.
- **Quiet gravity.** The subject is mortality and last-resort messaging; the design carries weight through restraint and precision, not drama or decoration.
- **Public-facing edges read plainly.** Invite links and recipient-facing copy must make sense to a non-technical person encountering Nostr for the first time.

## Accessibility & Inclusion

WCAG AA: body text ≥4.5:1 contrast (watch the muted-on-dark `--muted` against `--card`), large/bold text ≥3:1, status conveyed by more than color alone (the healthy/warning/triggered states pair a colored dot with a text label and shape — keep that redundancy). Fully keyboard-navigable forms with visible focus (amber border focus is in place). Every animation needs a `prefers-reduced-motion` alternative. Status colors (green/yellow/red) must remain distinguishable for common color-vision deficiencies via their text labels and position, not hue alone.
