package main

// sharedHead is the per-page <head> boilerplate (meta tags + font link).
// Every template starts with <head>` + sharedHead + `<title>…</title><style>` + baseCSS + `…`.
const sharedHead = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@500;600&family=JetBrains+Mono&display=swap" rel="stylesheet">`

// baseCSS is the shared design-token + element baseline for all admin/auth
// templates. Palette: warm tinted neutrals + amber accent (not the Tailwind-
// default AI look). Typography: IBM Plex Sans headings, system-sans body,
// JetBrains Mono for keys/npubs. Each template's <style> prepends this,
// then layers on its own specifics.
const baseCSS = `:root {
  --bg: #111110;
  --card: #1c1c1a;
  --border: #2a2a27;
  --text: #ecebe6;
  --muted: #8a8578;
  --accent: #d4a24c;
  --accent-ink: #1a1608;
  --green: #6fa86a;
  --yellow: #d6a441;
  --red: #d2685e;

  --font-heading: "IBM Plex Sans", ui-sans-serif, system-ui, sans-serif;
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
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  padding: 2rem 1rem;
  display: flex;
  justify-content: center;
  align-items: flex-start;
  -webkit-font-smoothing: antialiased;
}
h1, h2, h3 { font-family: var(--font-heading); font-weight: 500; letter-spacing: -0.005em; }
h1 {
  font-size: var(--text-xl);
  margin-bottom: 1.25rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
h2 {
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
  margin-bottom: 0.75rem;
  font-weight: 500;
}
a { color: var(--accent); }
code, pre { font-family: var(--font-mono); }

.container { max-width: 480px; width: 100%; }

.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  padding: 1.25rem;
  margin-bottom: 1rem;
}
.card-title {
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
  margin-bottom: 0.75rem;
  font-weight: 500;
}

.npub {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--muted);
  font-weight: 400;
}

.footer {
  text-align: center;
  font-size: var(--text-xs);
  color: var(--muted);
  margin-top: 1rem;
}
.footer a { color: var(--muted); }

.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.25rem 0.75rem;
  border-radius: 9999px;
  font-size: var(--text-xs);
  font-weight: 500;
}
.status-dot { width: 8px; height: 8px; border-radius: 50%; }
.status-healthy .status-dot { background: var(--green); box-shadow: 0 0 8px var(--green); }
.status-healthy { background: rgba(111,168,106,0.1); color: var(--green); }
.status-warning .status-dot { background: var(--yellow); box-shadow: 0 0 8px var(--yellow); }
.status-warning { background: rgba(214,164,65,0.1); color: var(--yellow); }
.status-triggered .status-dot { background: var(--red); box-shadow: 0 0 8px var(--red); }
.status-triggered { background: rgba(210,104,94,0.1); color: var(--red); }

.warn-banner {
  background: rgba(214,164,65,0.06);
  border-left: 3px solid var(--yellow);
  padding: 0.75rem 1rem;
  border-radius: 0 0.25rem 0.25rem 0;
  margin-bottom: 1rem;
}
.warn-banner-header {
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--yellow);
  margin-bottom: 0.5rem;
  font-weight: 500;
}
.warn-row { padding: 0.4rem 0; border-bottom: 1px solid rgba(214,164,65,0.12); }
.warn-row:first-of-type { padding-top: 0.2rem; }
.warn-row:last-child { border-bottom: none; padding-bottom: 0.2rem; }
.warn-title { font-size: var(--text-sm); font-weight: 600; color: var(--yellow); margin-bottom: 0.2rem; }
.warn-detail { font-size: var(--text-xs); color: var(--muted); line-height: 1.4; }

input, textarea, select {
  font-family: inherit;
  font-size: var(--text-sm);
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 0.4rem;
  color: var(--text);
  padding: 0.55rem 0.65rem;
}
input:focus, textarea:focus, select:focus { outline: none; border-color: var(--accent); }
textarea { font-family: var(--font-mono); resize: vertical; line-height: 1.4; }

.btn, a.btn, .actions form > button {
  display: inline-block;
  padding: 0.6rem 0.75rem;
  border-radius: 0.4rem;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text);
  text-decoration: none;
  text-align: center;
  font-size: var(--text-sm);
  font-weight: 500;
  cursor: pointer;
  font-family: inherit;
  transition: border-color 120ms ease-out, color 120ms ease-out;
}
.btn:hover, a.btn:hover, .actions form > button:hover { border-color: var(--accent); color: var(--accent); }

.actions {
  display: grid;
  grid-auto-flow: column;
  grid-auto-columns: 1fr;
  gap: 0.5rem;
  margin-top: 1rem;
}
.actions form { margin: 0; }
.actions form > button { width: 100%; }
`
