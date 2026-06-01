package main

import (
	"html/template"
	"net/http"
	"strings"
)

// signupData drives signupClosedTemplate. Invalid switches the copy from
// the friendly "invite-only host" message to an "invalid code" message;
// both render with the same neutral styling (no scary error banner).
type signupData struct {
	Npub     string
	FullNpub string
	Invalid  bool
}

// handleSignupLanding is the arrival path for a session whose npub is not
// (yet) whitelisted. With a valid unused ?code= it self-enrolls the npub
// as plan=invite and sends them to /admin/watcher to bootstrap a key.
// Without a code, an unknown code, or a code already spent by someone
// else, it renders a friendly closed page showing their npub so they can
// share it with the operator.
func (d *DeadManSwitch) handleSignupLanding(w http.ResponseWriter, r *http.Request) {
	if !d.cfg.FederationV1 {
		http.Error(w, "federation-only", http.StatusServiceUnavailable)
		return
	}
	pubkey := d.sessions.pubkeyFromRequest(r)
	npub, err := formatNpub(pubkey)
	if err != nil {
		http.Error(w, "bad session pubkey", http.StatusInternalServerError)
		return
	}
	if d.registry == nil {
		http.Error(w, "registry unavailable", http.StatusServiceUnavailable)
		return
	}
	// Already whitelisted users don't need to sign up.
	if d.registry.IsWhitelisted(npub) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" || d.invites == nil {
		d.renderSignupClosed(w, npub, false)
		return
	}

	if usedBy, used := d.invites.IsUsedBy(code); used {
		if usedBy == npub {
			// Idempotent re-entry: re-enroll (Redeem is a no-op for the same
			// npub) and continue to the bootstrap flow.
			d.enrollInvite(w, r, npub, code)
			return
		}
		// Spent by someone else (or revoked): invalid-code variant.
		d.renderSignupClosed(w, npub, true)
		return
	}

	if !d.invites.IsValid(code) {
		// Unknown code — treat as a friendly closed arrival, not an error.
		d.renderSignupClosed(w, npub, false)
		return
	}

	d.enrollInvite(w, r, npub, code)
}

// enrollInvite admits npub via code: whitelist + plan=invite first, then
// the atomic Redeem. If Redeem loses a race (another npub spent the code
// between the validity check and here), roll the whitelist add back and
// show the invalid-code page. tryStart returns ErrNotEnrolled here (no
// config yet), which is expected — the user bootstraps at /admin/watcher.
func (d *DeadManSwitch) enrollInvite(w http.ResponseWriter, r *http.Request, npub, code string) {
	wl := d.registry.Whitelist()
	if err := wl.Add(npub, "invite:"+code); err != nil {
		http.Error(w, "enroll failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := wl.SetPlanKind(npub, "invite"); err != nil {
		http.Error(w, "enroll failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := d.invites.Redeem(code, npub); err != nil {
		// Lost the race or code became invalid — undo the whitelist add.
		_ = wl.Remove(npub)
		d.renderSignupClosed(w, npub, true)
		return
	}
	_ = d.registry.tryStart(npub)
	http.Redirect(w, r, "/admin/watcher", http.StatusSeeOther)
}

func (d *DeadManSwitch) renderSignupClosed(w http.ResponseWriter, npub string, invalid bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	signupClosedTemplate.Execute(w, signupData{
		Npub:     truncateMiddle(npub, 24),
		FullNpub: npub,
		Invalid:  invalid,
	})
}

var signupClosedTemplate = template.Must(template.New("signupClosed").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
` + sharedHead + `
<title>Invite only · Dead Man's Switch</title>
<style>` + baseCSS + `
  body { align-items: center; }
  .container { max-width: 480px; }
  h1 { margin-bottom: 0.5rem; }
  .lead { color: var(--ink-muted); font-size: var(--text-sm); line-height: 1.6; margin-bottom: 1.25rem; }
  .label { font-family: var(--font-mono); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.12em; color: var(--ink-muted); margin-bottom: 0.5rem; }
  .npub-box { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--ink); word-break: break-all; background: var(--paper-2); border: 1px solid var(--rule); border-radius: 3px; padding: 0.7rem; user-select: all; }
  .hint { color: var(--ink-muted); font-size: var(--text-xs); margin-top: 0.75rem; line-height: 1.5; }
</style>
</head>
<body>
<div class="container">
  {{if .Invalid}}
  <h1>That invite can't be used</h1>
  <p class="lead">The invite code in your link is no longer valid — it may have already been redeemed by someone else, or been revoked. Ask the operator for a fresh code.</p>
  {{else}}
  <h1>This host is invite-only</h1>
  <p class="lead">You're signed in, but your npub isn't enrolled on this dead man's switch yet. Enrollment is by invite — send the operator your npub below and ask for an invite link.</p>
  {{end}}
  <div class="card">
    <div class="label">Your npub</div>
    <div class="npub-box" id="npub">{{.FullNpub}}</div>
    <div class="hint">Share this with the operator so they can grant you access or send an invite code.</div>
  </div>
  <div class="actions">
    <a class="btn" href="/">Status</a>
    <form method="POST" action="/logout"><button type="submit" class="btn">Sign out</button></form>
  </div>
</div>
</body>
</html>`))
