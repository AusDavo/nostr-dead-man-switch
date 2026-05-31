package main

import (
	"html/template"
	"net/http"
	"strings"
	"time"
)

// requireAdmin reports whether the request carries a session for the
// configured admin npub. It does not write a response — callers send 403
// when ok is false. Admin status requires federation mode, a live
// registry, a configured admin_npub, and a session pubkey that matches it.
func (d *DeadManSwitch) requireAdmin(r *http.Request) (pubkey, npub string, ok bool) {
	if !d.cfg.FederationV1 || d.registry == nil {
		return "", "", false
	}
	if d.cfg.adminPubkeyHex == "" {
		return "", "", false
	}
	pubkey = d.sessions.pubkeyFromRequest(r)
	if pubkey == "" || pubkey != d.cfg.adminPubkeyHex {
		return "", "", false
	}
	npub, err := formatNpub(pubkey)
	if err != nil {
		return "", "", false
	}
	return pubkey, npub, true
}

// requireAdminPost layers the admin-identity check on top of
// requireFederationPost (method/mode/session/CSRF). Returns ok=false with
// the response already written when any gate fails.
func (d *DeadManSwitch) requireAdminPost(w http.ResponseWriter, r *http.Request) (pubkey, npub string, ok bool) {
	pubkey, npub, ok = d.requireFederationPost(w, r)
	if !ok {
		return "", "", false
	}
	if d.cfg.adminPubkeyHex == "" || pubkey != d.cfg.adminPubkeyHex {
		http.Error(w, "forbidden", http.StatusForbidden)
		return "", "", false
	}
	return pubkey, npub, true
}

type rosterRow struct {
	Npub     string
	FullNpub string
	PlanKind string
	AddedAt  string
	Running  bool
	LastSeen string
}

type rosterData struct {
	Npub    string
	CSRF    string
	Rows    []rosterRow
	Codes   []InviteCodeView
	NewCode string
	Flash   string
}

// handleRoster renders the admin roster: enrolled users (plan, added,
// running, last-seen) plus invite codes, with grant/mint/revoke forms.
func (d *DeadManSwitch) handleRoster(w http.ResponseWriter, r *http.Request) {
	pubkey, npub, ok := d.requireAdmin(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	loc := d.cfg.location
	if loc == nil {
		loc = time.UTC
	}
	tfmt := "2006-01-02 15:04 MST"

	wl := d.registry.Whitelist()
	entries := wl.List()
	rows := make([]rosterRow, 0, len(entries))
	for _, e := range entries {
		plan := e.PlanKind
		if plan == "" {
			plan = "—"
		}
		row := rosterRow{
			Npub:     truncateMiddle(e.Npub, 24),
			FullNpub: e.Npub,
			PlanKind: plan,
			AddedAt:  e.AddedAt.In(loc).Format(tfmt),
			Running:  d.registry.IsRunning(e.Npub),
			LastSeen: "—",
		}
		if wch := d.registry.Get(e.Npub); wch != nil {
			if snap := wch.Snapshot(); !snap.LastSeen.IsZero() {
				row.LastSeen = snap.LastSeen.In(loc).Format(tfmt)
			}
		}
		rows = append(rows, row)
	}

	var codes []InviteCodeView
	if d.invites != nil {
		codes = d.invites.ListCodes()
	}

	data := rosterData{
		Npub:    truncateMiddle(npub, 24),
		CSRF:    d.sessions.issueCSRFToken(pubkey),
		Rows:    rows,
		Codes:   codes,
		NewCode: strings.TrimSpace(r.URL.Query().Get("new_code")),
		Flash:   strings.TrimSpace(r.URL.Query().Get("flash")),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	rosterTemplate.Execute(w, data)
}

// handleRosterGrant admits a typed npub as plan=free and starts its
// watcher (which no-ops until the user bootstraps a key). Bad input
// bounces back to the roster with a flash.
func (d *DeadManSwitch) handleRosterGrant(w http.ResponseWriter, r *http.Request) {
	_, _, ok := d.requireAdminPost(w, r)
	if !ok {
		return
	}
	npub := strings.TrimSpace(r.FormValue("npub"))
	if err := validateNpub(npub); err != nil {
		http.Redirect(w, r, "/admin/roster?flash=Invalid+npub", http.StatusSeeOther)
		return
	}
	wl := d.registry.Whitelist()
	if err := wl.Add(npub, "granted by admin"); err != nil {
		http.Redirect(w, r, "/admin/roster?flash=Grant+failed", http.StatusSeeOther)
		return
	}
	if err := wl.SetPlanKind(npub, "free"); err != nil {
		http.Redirect(w, r, "/admin/roster?flash=Grant+failed", http.StatusSeeOther)
		return
	}
	_ = d.registry.tryStart(npub)
	http.Redirect(w, r, "/admin/roster", http.StatusSeeOther)
}

// handleRosterRevoke tears down an enrolled npub. The teardown order is
// the load-bearing safety invariant: Stop → DeleteUser → Remove. It must
// never reach the action dispatch (only UserWatcher.evaluate may).
func (d *DeadManSwitch) handleRosterRevoke(w http.ResponseWriter, r *http.Request) {
	_, _, ok := d.requireAdminPost(w, r)
	if !ok {
		return
	}
	npub := strings.TrimSpace(r.FormValue("npub"))
	if err := validateNpub(npub); err != nil {
		http.Redirect(w, r, "/admin/roster?flash=Invalid+npub", http.StatusSeeOther)
		return
	}
	// INVARIANT teardown order — see user_watcher.go execActions comment.
	if err := d.registry.Stop(npub); err != nil {
		http.Redirect(w, r, "/admin/roster?flash=Revoke+failed", http.StatusSeeOther)
		return
	}
	if err := d.registry.Store().DeleteUser(npub); err != nil {
		http.Redirect(w, r, "/admin/roster?flash=Revoke+failed", http.StatusSeeOther)
		return
	}
	if err := d.registry.Whitelist().Remove(npub); err != nil {
		http.Redirect(w, r, "/admin/roster?flash=Revoke+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/roster", http.StatusSeeOther)
}

// handleRosterInviteNew mints a fresh invite code and shows it once via a
// query param on the roster redirect.
func (d *DeadManSwitch) handleRosterInviteNew(w http.ResponseWriter, r *http.Request) {
	_, _, ok := d.requireAdminPost(w, r)
	if !ok {
		return
	}
	if d.invites == nil {
		http.Redirect(w, r, "/admin/roster?flash=Invite+codes+unavailable", http.StatusSeeOther)
		return
	}
	code, err := d.invites.Mint()
	if err != nil {
		http.Redirect(w, r, "/admin/roster?flash=Mint+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/roster?new_code="+code, http.StatusSeeOther)
}

// handleRosterInviteRevoke marks an invite code revoked so it can never
// be redeemed.
func (d *DeadManSwitch) handleRosterInviteRevoke(w http.ResponseWriter, r *http.Request) {
	_, _, ok := d.requireAdminPost(w, r)
	if !ok {
		return
	}
	if d.invites == nil {
		http.Redirect(w, r, "/admin/roster?flash=Invite+codes+unavailable", http.StatusSeeOther)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" {
		http.Redirect(w, r, "/admin/roster?flash=Missing+code", http.StatusSeeOther)
		return
	}
	if err := d.invites.RevokeCode(code); err != nil {
		http.Redirect(w, r, "/admin/roster?flash=Revoke+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/roster", http.StatusSeeOther)
}

var rosterTemplate = template.Must(template.New("roster").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
` + sharedHead + `
<title>Roster · Dead Man's Switch</title>
<style>` + baseCSS + `
  .container { max-width: 760px; }
  h1 { justify-content: space-between; }
  table { width: 100%; border-collapse: collapse; font-size: var(--text-sm); }
  th, td { text-align: left; padding: 0.5rem 0.5rem; border-bottom: 1px solid var(--border); }
  th { font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); font-weight: 500; }
  td.npub, td.code { font-family: var(--font-mono); font-size: var(--text-xs); word-break: break-all; }
  .pill { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 9999px; font-size: var(--text-xs); border: 1px solid var(--border); }
  .pill.run { color: var(--green); border-color: rgba(111,168,106,0.4); }
  .pill.stop { color: var(--muted); }
  .pill.redeemed { color: var(--muted); }
  .pill.revoked { color: var(--red); border-color: rgba(210,104,94,0.4); }
  .pill.available { color: var(--green); border-color: rgba(111,168,106,0.4); }
  .muted { color: var(--muted); font-size: var(--text-xs); line-height: 1.5; margin-bottom: 0.75rem; }
  .flash { background: rgba(214,164,65,0.08); border: 1px solid rgba(214,164,65,0.4); color: var(--yellow); padding: 0.6rem 0.75rem; border-radius: 0.4rem; font-size: var(--text-sm); margin-bottom: 1rem; }
  .newcode { background: rgba(111,168,106,0.08); border: 1px solid rgba(111,168,106,0.4); color: var(--text); padding: 0.75rem; border-radius: 0.4rem; margin-bottom: 1rem; }
  .newcode code { font-family: var(--font-mono); font-size: var(--text-base); color: var(--accent); user-select: all; }
  form.inline { display: flex; gap: 0.5rem; align-items: center; margin: 0; }
  form.inline input[type=text] { flex: 1; }
  button.primary { padding: 0.5rem 0.85rem; border-radius: 0.4rem; border: 1px solid var(--accent); background: var(--accent); color: var(--accent-ink); font-size: var(--text-sm); font-weight: 600; cursor: pointer; font-family: inherit; }
  button.primary:hover { filter: brightness(1.05); }
  button.danger { padding: 0.35rem 0.6rem; border-radius: 0.4rem; background: transparent; color: var(--red); border: 1px solid rgba(210,104,94,0.4); font-size: var(--text-xs); cursor: pointer; font-family: inherit; }
  button.danger:hover { background: rgba(210,104,94,0.08); }
  .empty { color: var(--muted); font-style: italic; padding: 0.5rem 0; }
  .card-title { font-size: var(--text-sm); font-weight: 600; color: var(--text); text-transform: none; letter-spacing: normal; margin-bottom: 0.75rem; }
</style>
</head>
<body>
<div class="container">
  <h1>Roster <span class="npub">{{.Npub}}</span></h1>

  {{if .Flash}}<div class="flash">{{.Flash}}</div>{{end}}
  {{if .NewCode}}<div class="newcode">New invite code (copy it now): <code>{{.NewCode}}</code><div class="muted" style="margin-top:0.4rem">Share <code style="font-size:var(--text-xs)">/admin/signup?code={{.NewCode}}</code> with the person you're inviting.</div></div>{{end}}

  <div class="card">
    <div class="card-title">Enrolled users ({{len .Rows}})</div>
    {{if .Rows}}
    <table>
      <thead><tr><th>npub</th><th>plan</th><th>added</th><th>state</th><th>last seen</th><th></th></tr></thead>
      <tbody>
      {{range .Rows}}
      <tr>
        <td class="npub">{{.Npub}}</td>
        <td>{{.PlanKind}}</td>
        <td>{{.AddedAt}}</td>
        <td>{{if .Running}}<span class="pill run">running</span>{{else}}<span class="pill stop">stopped</span>{{end}}</td>
        <td>{{.LastSeen}}</td>
        <td>
          <form class="inline" method="POST" action="/admin/roster/revoke" onsubmit="return confirm('Revoke {{.FullNpub}}? This stops the watcher and deletes their stored config and key.');">
            <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
            <input type="hidden" name="npub" value="{{.FullNpub}}">
            <button type="submit" class="danger">Revoke</button>
          </form>
        </td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="empty">No users enrolled.</div>
    {{end}}
  </div>

  <div class="card">
    <div class="card-title">Grant access</div>
    <div class="muted">Add an npub directly as a free user. They'll be able to sign in and bootstrap a watcher key.</div>
    <form class="inline" method="POST" action="/admin/roster/grant">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <input type="text" name="npub" placeholder="npub1…" spellcheck="false" required>
      <button type="submit" class="primary">Grant</button>
    </form>
  </div>

  <div class="card">
    <div class="card-title">Invite codes</div>
    <div class="muted">Mint a single-use code and share the signup link. Anyone who redeems it self-enrolls as an invite user.</div>
    <form method="POST" action="/admin/roster/invite/new" style="margin-bottom:1rem">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <button type="submit" class="primary">Mint new code</button>
    </form>
    {{if .Codes}}
    <table>
      <thead><tr><th>code</th><th>source</th><th>state</th><th>redeemed by</th><th></th></tr></thead>
      <tbody>
      {{range .Codes}}
      <tr>
        <td class="code">{{.Code}}</td>
        <td>{{.Source}}</td>
        <td><span class="pill {{.State}}">{{.State}}</span></td>
        <td class="npub">{{if .UsedBy}}{{.UsedBy}}{{else}}—{{end}}</td>
        <td>
          {{if eq .State "available"}}
          <form class="inline" method="POST" action="/admin/roster/invite/revoke">
            <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
            <input type="hidden" name="code" value="{{.Code}}">
            <button type="submit" class="danger">Revoke</button>
          </form>
          {{end}}
        </td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="empty">No invite codes yet.</div>
    {{end}}
  </div>

  <div class="actions">
    <a class="btn" href="/admin">Admin</a>
    <a class="btn" href="/">Status</a>
    <form method="POST" action="/logout"><button type="submit" class="btn">Sign out</button></form>
  </div>
</div>
</body>
</html>`))
