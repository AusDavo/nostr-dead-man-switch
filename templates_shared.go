package main

// sharedHead is the per-page <head> boilerplate (meta tags + font link).
// Every template starts with <head>` + sharedHead + `<title>…</title><style>` + baseCSS + `…`.
const sharedHead = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Newsreader:opsz,wght@6..72,400;6..72,500;6..72,600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">`

// baseCSS is the shared design-token + element baseline for all admin/auth
// templates. Direction: a LIGHT "document" system (certificate / will / legal
// instrument) — see DESIGN.md. Palette: true near-neutral paper + near-black
// ink + dominant oxblood accent; status colors darkened for light bg. Type:
// Newsreader serif (display/figures), system sans (body), JetBrains Mono
// (protocol values + structural labels). Layout: rules, not cards.
//
// TOKENS: --paper / --paper-2 / --ink / --ink-muted / --rule / --oxblood are
// the surface + ink + accent vocabulary; --green / --yellow / --red carry
// semantic state (always paired with a text label, never color alone). Every
// template's <style> prepends this, then layers its own.
const baseCSS = `:root {
  /* surface, ink, accent */
  --paper: #f3f2ef;
  --paper-2: #eceae6;
  --ink: #19181a;
  --ink-muted: #57555a;
  --rule: #c9c6c0;
  --oxblood: #7a1f1a;

  /* semantic state (darkened for light bg) */
  --green: #2f6b3a;
  --yellow: #8a5a12;
  --red: #9c241c;

  --font-heading: "Newsreader", Georgia, "Times New Roman", serif;
  --font-serif: "Newsreader", Georgia, "Times New Roman", serif;
  --font-body: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;

  --text-xs: 0.75rem;
  --text-sm: 0.875rem;
  --text-base: 1rem;
  --text-lg: 1.125rem;
  --text-xl: 1.375rem;
  --text-2xl: 1.75rem;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: var(--font-body);
  background: var(--paper);
  color: var(--ink);
  min-height: 100vh;
  padding: 3rem 1.25rem;
  display: flex;
  justify-content: center;
  align-items: flex-start;
  -webkit-font-smoothing: antialiased;
  line-height: 1.5;
}
h1, h2, h3 { font-family: var(--font-heading); font-weight: 500; }
/* h1 is the document masthead: serif title + optional status stamp, closed
   by a double rule the way an official document opens. */
h1 {
  font-family: var(--font-serif);
  font-size: 1.85rem;
  font-weight: 500;
  letter-spacing: -0.01em;
  line-height: 1.05;
  text-wrap: balance;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
  padding-bottom: 0.9rem;
  margin-bottom: 1.4rem;
  border-bottom: 3px double var(--ink);
}
/* h2 / .card-title: small mono structural label, like a section header on a
   printed statement. */
h2, .card-title {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--ink-muted);
  margin-bottom: 1rem;
}
h3 { font-size: var(--text-lg); letter-spacing: -0.005em; }
a { color: var(--oxblood); text-decoration: underline; text-underline-offset: 2px; text-decoration-thickness: 1px; }
a:hover { text-decoration-thickness: 2px; }
code, pre { font-family: var(--font-mono); }

.container { max-width: 540px; width: 100%; }

/* Cards are not boxes here: each is a titled section separated by a hairline
   rule, like the divisions of a document. */
.card {
  background: transparent;
  border: none;
  border-bottom: 1px solid var(--rule);
  border-radius: 0;
  padding: 1.4rem 0;
  margin-bottom: 0;
}

.npub {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--ink-muted);
  font-weight: 400;
}

/* Colophon: fine-print footer in mono. */
.footer {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  letter-spacing: 0.02em;
  color: var(--ink-muted);
  padding-top: 1.4rem;
  text-align: center;
}
.footer a { color: var(--oxblood); }

/* Status stamp: a bordered, slightly-rotated label stamped onto the sheet.
   Color reinforces; the dot + word carry the meaning. */
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  padding: 0.3rem 0.6rem;
  border: 1.5px solid currentColor;
  border-radius: 2px;
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  font-weight: 500;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  transform: rotate(-1.5deg);
}
.status-dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; flex-shrink: 0; }
.status-healthy { color: var(--green); }
.status-warning { color: var(--yellow); }
.status-triggered { color: var(--red); }

/* Warning banner: a bordered inset block (no side-stripe). */
.warn-banner {
  background: rgba(138,90,18,0.06);
  border: 1px solid rgba(138,90,18,0.45);
  padding: 0.85rem 1rem;
  border-radius: 3px;
  margin-bottom: 1.4rem;
}
.warn-banner-header {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--yellow);
  margin-bottom: 0.5rem;
  font-weight: 500;
}
.warn-row { padding: 0.4rem 0; border-bottom: 1px solid rgba(138,90,18,0.18); }
.warn-row:first-of-type { padding-top: 0.2rem; }
.warn-row:last-child { border-bottom: none; padding-bottom: 0.2rem; }
.warn-title { font-size: var(--text-sm); font-weight: 600; color: var(--yellow); margin-bottom: 0.2rem; }
.warn-detail { font-size: var(--text-xs); color: var(--ink-muted); line-height: 1.4; }

input, textarea, select {
  font-family: inherit;
  font-size: var(--text-sm);
  background: var(--paper-2);
  border: 1px solid var(--rule);
  border-radius: 3px;
  color: var(--ink);
  padding: 0.55rem 0.65rem;
}
input:focus, textarea:focus, select:focus { outline: none; border-color: var(--oxblood); }
textarea { font-family: var(--font-mono); resize: vertical; line-height: 1.4; }

/* Buttons: ghost by default (ink outline, fills oxblood on hover); .primary
   is an oxblood fill; .danger is a red fill for irreversible actions. */
.btn, a.btn, .actions form > button {
  display: inline-block;
  padding: 0.6rem 0.85rem;
  border-radius: 3px;
  border: 1px solid var(--ink);
  background: transparent;
  color: var(--ink);
  text-decoration: none;
  text-align: center;
  font-size: var(--text-sm);
  font-weight: 500;
  cursor: pointer;
  font-family: inherit;
  transition: background-color 120ms ease-out, color 120ms ease-out, border-color 120ms ease-out;
}
.btn:hover, a.btn:hover, .actions form > button:hover { background: var(--oxblood); border-color: var(--oxblood); color: var(--paper); }
.btn.primary, a.btn.primary, button.primary { background: var(--oxblood); border-color: var(--oxblood); color: var(--paper); }
.btn.primary:hover, a.btn.primary:hover, button.primary:hover { filter: brightness(1.1); }
.btn.danger, a.btn.danger, button.danger { background: var(--red); border-color: var(--red); color: var(--paper); }
.btn.danger:hover, a.btn.danger:hover, button.danger:hover { filter: brightness(1.1); }
.btn.ghost, a.btn.ghost, button.ghost { background: transparent; border-color: var(--ink); color: var(--ink); }
.btn.ghost:hover, a.btn.ghost:hover, button.ghost:hover { background: var(--oxblood); border-color: var(--oxblood); color: var(--paper); }

.actions {
  display: grid;
  grid-auto-flow: column;
  grid-auto-columns: 1fr;
  gap: 0.5rem;
  margin-top: 1rem;
}
.actions form { margin: 0; }
.actions form > button { width: 100%; }

@media (prefers-reduced-motion: reduce) {
  .status-badge { transform: none; }
  * { transition: none !important; }
}
`
