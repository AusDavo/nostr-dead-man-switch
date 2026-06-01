# Design

A **light document** system: the UI reads like a certificate / statement / legal instrument, not a dashboard. The product is a dead man's switch — instructions that execute when you can no longer act — so the interface carries that weight by looking like something you're meant to read and trust. Cypherpunk/terminal personality (sovereign, precise, unflinching) is expressed through monospace protocol values and stark structure, rendered on paper rather than in a terminal. Register: product. Target WCAG AA.

Anti-references still hold: not a generic SaaS/Tailwind dashboard, not crypto-bro neon, not an enterprise admin console. Added by this direction: not a warm AI-cream "editorial" page — the paper is a true near-neutral, never a warm parchment tint.

## Theme

Light, single theme. Near-neutral paper field, near-black ink, generous margins, a single focused column (~540px) that reads top-to-bottom like a sheet. No cards: structure comes from horizontal rules and labeled rows, the way a printed statement or will is organized. The mood is grave and documentary when calm; arresting (an oxblood stamp on a document) when triggered.

## Color

OKLCH is the source of truth; hex in parentheses is the sRGB fallback. The paper is chroma ~0 (deliberately NOT cream/parchment). Oxblood is the dominant serious accent; status colors are darkened so they read on light. All text pairings verified ≥4.5:1 (body sits at 6.6:1).

### Surface & ink
- `--paper`     oklch(0.962 0.001 90) (#f3f2ef) — body / sheet background
- `--paper-2`   oklch(0.935 0.002 90) (#eceae6) — inset fill, subtle blocks
- `--ink`       oklch(0.205 0.004 300) (#19181a) — primary ink (15.8:1)
- `--ink-muted` oklch(0.470 0.004 300) (#57555a) — secondary ink, labels (6.6:1)
- `--rule`      oklch(0.835 0.004 80) (#c9c6c0) — hairline rules, dotted leaders

### Accent (dominant)
- `--oxblood`   oklch(0.385 0.135 25) (#7a1f1a) — the serious signal: links, primary actions, the masthead rule weight, the "armed/triggered" register. Used deliberately, not everywhere (9.2:1).

### Status (semantic, never color-alone)
State is carried by a **stamp**: a bordered, slightly-rotated label with a dot, plus the word. Color reinforces, position and text label carry meaning. Darkened for light bg:
- `--green`  oklch(0.500 0.085 150) (#2f6b3a) — ALIVE / healthy (5.7:1)
- `--amber`  oklch(0.520 0.095 70)  (#8a5a12) — WARNING, DMs sent (5.3:1)
- `--red`    oklch(0.470 0.155 27)  (#9c241c) — TRIGGERED / fired (7.0:1)

## Typography

Three families on contrast axes (literary serif display vs. system body vs. mono):
- **Display / figures / headings** — `"Newsreader"` (a literary serif with optical sizing), weights 400/500/600. Carries the "document" character: page title, the big timer figures. `text-wrap: balance` on headings.
- **Body** — system sans (`ui-sans-serif, system-ui, -apple-system, "Segoe UI"`) for labels and prose. Quiet, neutral, fast.
- **Mono** — `"JetBrains Mono"` for every protocol value AND for structural labels (section labels, eyebrows, stamp text, colophon): npubs, relay URLs, timestamps, thresholds. Mono is the "this is a real, recorded value" voice and the terminal thread through the document.

Scale leans on serif size + the serif/mono/sans split for hierarchy, not weight alone. Big serif figures (timer values ~2.4rem) anchor each section; everything else is calm. Structural labels are small mono, uppercase, tracked ~0.14em — acceptable as functional document labels (a statement has section headers), not decorative eyebrows on marketing sections.

## Components

- **Masthead** — serif page title + a mono sub-line, separated from the body by a 3px **double rule** (`border-bottom: 3px double var(--ink)`), the way an official document opens. The status stamp sits top-right.
- **Status stamp** — bordered box (1.5px solid in the state color), state color text + dot, mono uppercase, rotated ~-1.5deg so it reads as stamped onto the sheet. The single most prominent state indicator. TRIGGERED = red stamp, the deliberately arresting moment.
- **Section** — a titled block separated by 1px `--rule` hairlines. No cards, never nested. Section label is small mono uppercase in `--ink-muted`.
- **Timer figures** — two large serif numbers (silent-for / triggers-in) in a 2-col grid, the visual anchor of the status sheet.
- **Dotted-leader row** — label (`--ink-muted`) … dotted leader … value (mono), like a line item in an invoice or a table of contents. The default key/value affordance.
- **Relay / list row** — state dot + mono URL; down relays drop to `--ink-muted`.
- **Buttons** — primary: oxblood fill, paper text. Ghost: 1px `--ink` border, ink text, hover fills oxblood. Destructive/irreversible: oxblood fill + confirmation that names the consequence. Inputs: paper-2 fill, 1px `--rule`, oxblood border on focus (visible focus required).
- **Colophon** — fine-print footer in mono, `--ink-muted`, with oxblood underlined links. "Running since…", /health, sign in.

## Layout

Single centered sheet, `max-width: ~540px`, body padding ~`3rem 1.25rem`, content top-aligned. Sections stack with rule separators; rhythm from vertical padding, not boxes. Flexbox for rows (masthead, leaders, relays), grid only for the 2-col timer figures. Mobile: the sheet narrows cleanly; long npubs/relay URLs wrap or scroll within their mono span rather than overflowing; the timer figures stack to one column under ~420px.

## Motion

Minimal and documentary. Allowed: a subtle ink-draw or fade on the masthead rule, 120ms ease-out on interactive border/color (links, buttons, inputs), and the status stamp may settle in with a tiny rotation/opacity on first load. No layout animation, no scroll reveals. Every motion needs a `@media (prefers-reduced-motion: reduce)` fallback (instant, no rotation). Easing: ease-out only.

## Irreversibility (product-specific)

Triggering is destructive and final, and on this surface it is the most visually charged moment: a red TRIGGERED stamp on what otherwise looks like a calm legal document. Destructive/irreversible actions (manual trigger, delete enrollment, reset) get an oxblood affordance and a confirmation step that names exactly what will happen in plain words ("this will send all configured emails and publish your notes — it cannot be undone"). Friction is proportional to consequence by design.

## Recipient-facing edges

Invite / signup / recipient pages are opened by non-technical people (a spouse, lawyer, executor). The document aesthetic is an asset here: it should read as a serious, trustworthy instrument, not an admin panel. Keep copy plain, define Nostr terms in passing, and never assume the reader knows what an npub or relay is.
