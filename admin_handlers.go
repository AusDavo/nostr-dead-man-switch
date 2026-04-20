package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// testActionCooldown rate-limits /admin/config/test-action per pubkey so
// a wedged form can't hammer a user's SMTP provider into blocking them.
const testActionCooldown = 2 * time.Second

// testActionGate tracks the last test-action time per session pubkey. The
// zero value is usable; Allow initialises the map lazily.
type testActionGate struct {
	mu      sync.Mutex
	lastFor map[string]time.Time
}

func (g *testActionGate) Allow(pubkey string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lastFor == nil {
		g.lastFor = make(map[string]time.Time)
	}
	if prev, ok := g.lastFor[pubkey]; ok && now.Sub(prev) < testActionCooldown {
		return false
	}
	g.lastFor[pubkey] = now
	return true
}

type watcherSetupData struct {
	Npub         string
	FullNpub     string
	CSRF         string
	AlreadySetup bool
	WatcherNpub  string // bot pubkey in npub form, always populated when AlreadySetup
}

type watcherGeneratedData struct {
	Npub     string
	FullNpub string
	Nsec     string
	Pubnpub  string
}

// handleWatcherSetup renders the bootstrap UI. In federation mode, a
// whitelisted user with no sealed nsec sees two forms (generate or
// import). A user who already has a sealed nsec sees an "already set up"
// confirmation.
func (d *DeadManSwitch) handleWatcherSetup(w http.ResponseWriter, r *http.Request) {
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
	store := d.registry.Store()
	if store == nil {
		http.Error(w, "user store unavailable", http.StatusServiceUnavailable)
		return
	}

	data := watcherSetupData{
		Npub:         truncateMiddle(npub, 24),
		FullNpub:     npub,
		CSRF:         d.sessions.issueCSRFToken(pubkey),
		AlreadySetup: store.HasSealedNsec(npub),
	}
	if data.AlreadySetup {
		if uc, err := store.LoadConfig(npub); err == nil && uc != nil {
			if botNpub, err := nip19.EncodePublicKey(uc.WatcherPubkeyHex); err == nil {
				data.WatcherNpub = botNpub
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	watcherSetupTemplate.Execute(w, data)
}

// handleWatcherGenerate creates a fresh bot keypair for the session's
// npub, seals the nsec, seeds a default UserConfig, and starts the
// watcher. The plaintext nsec is rendered inline exactly once and never
// written to logs or session storage.
func (d *DeadManSwitch) handleWatcherGenerate(w http.ResponseWriter, r *http.Request) {
	_, npub, ok := d.requireFederationPost(w, r)
	if !ok {
		return
	}
	store := d.registry.Store()
	sealer := d.registry.Sealer()
	if store == nil || sealer == nil {
		http.Error(w, "federation infrastructure unavailable", http.StatusServiceUnavailable)
		return
	}
	if store.HasSealedNsec(npub) {
		http.Error(w, "watcher already configured for this npub", http.StatusConflict)
		return
	}

	sk := nostr.GeneratePrivateKey()
	pkHex, err := nostr.GetPublicKey(sk)
	if err != nil {
		http.Error(w, "pubkey derivation failed", http.StatusInternalServerError)
		return
	}
	nsec, err := nip19.EncodePrivateKey(sk)
	if err != nil {
		http.Error(w, "nsec encoding failed", http.StatusInternalServerError)
		return
	}
	botNpub, err := nip19.EncodePublicKey(pkHex)
	if err != nil {
		http.Error(w, "bot npub encoding failed", http.StatusInternalServerError)
		return
	}

	if err := d.enrollWatcher(npub, sk, pkHex); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	watcherGeneratedTemplate.Execute(w, watcherGeneratedData{
		Npub:     truncateMiddle(npub, 24),
		FullNpub: npub,
		Nsec:     nsec,
		Pubnpub:  botNpub,
	})
}

const watcherRevealMaxBytes = 16 * 1024

// handleWatcherRevealChallenge issues a fresh challenge for the
// reveal-nsec flow. It's a separate challenge from /login/challenge so a
// stolen session cookie alone can't unseal — the holder must also sign a
// fresh NIP-07 event with the session pubkey's key material.
func (d *DeadManSwitch) handleWatcherRevealChallenge(w http.ResponseWriter, r *http.Request) {
	if !d.cfg.FederationV1 {
		http.Error(w, "federation-only", http.StatusServiceUnavailable)
		return
	}
	if d.challenges == nil {
		http.Error(w, "challenge store unavailable", http.StatusServiceUnavailable)
		return
	}
	c, err := d.challenges.issue()
	if err != nil {
		http.Error(w, "challenge error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{"challenge": c})
}

// handleWatcherReveal verifies a signed challenge from the session
// pubkey and returns the unsealed nsec as JSON. Both gates are required:
// CSRF (cookie-bound) and a fresh NIP-07 signature (key-bound). Either
// alone is insufficient.
func (d *DeadManSwitch) handleWatcherReveal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !d.cfg.FederationV1 {
		http.Error(w, "federation-only", http.StatusServiceUnavailable)
		return
	}
	if d.sessions == nil || d.challenges == nil || d.registry == nil {
		http.Error(w, "reveal unavailable", http.StatusServiceUnavailable)
		return
	}
	pubkey := d.sessions.pubkeyFromRequest(r)
	if pubkey == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("X-CSRF-Token")
	if token == "" || !d.sessions.verifyCSRFToken(pubkey, token) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	npub, err := formatNpub(pubkey)
	if err != nil {
		http.Error(w, "bad session pubkey", http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, watcherRevealMaxBytes))
	if err != nil {
		http.Error(w, "body too large", http.StatusBadRequest)
		return
	}
	var payload struct {
		SignedEvent json.RawMessage `json:"signedEvent"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.SignedEvent) == 0 {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	var peek struct {
		Tags [][]string `json:"tags"`
	}
	if err := json.Unmarshal(payload.SignedEvent, &peek); err != nil {
		http.Error(w, "invalid event", http.StatusBadRequest)
		return
	}
	var challenge string
	for _, t := range peek.Tags {
		if len(t) >= 2 && t[0] == "challenge" {
			challenge = t[1]
			break
		}
	}
	if challenge == "" || !d.challenges.consume(challenge) {
		http.Error(w, "unknown or expired challenge", http.StatusBadRequest)
		return
	}
	// Tight binding: signer must be exactly the session pubkey. This blocks
	// cross-account reveal attempts even if the attacker has a whitelisted
	// extension identity.
	if _, err := verifyAuthEvent(payload.SignedEvent, challenge, pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	store := d.registry.Store()
	sealer := d.registry.Sealer()
	if store == nil || sealer == nil {
		http.Error(w, "federation infrastructure unavailable", http.StatusServiceUnavailable)
		return
	}
	sealed, err := store.LoadSealedNsec(npub)
	if err != nil {
		http.Error(w, "no sealed nsec on file", http.StatusNotFound)
		return
	}
	skBytes, err := sealer.Unseal(npub, sealed)
	if err != nil {
		http.Error(w, "unseal failed", http.StatusInternalServerError)
		return
	}
	nsec, err := nip19.EncodePrivateKey(string(skBytes))
	if err != nil {
		http.Error(w, "nsec encoding failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(map[string]string{"nsec": nsec})
}

// handleWatcherImport accepts an existing nsec, seals it, seeds a
// default UserConfig, and starts the watcher. On success redirects to
// /admin.
func (d *DeadManSwitch) handleWatcherImport(w http.ResponseWriter, r *http.Request) {
	_, npub, ok := d.requireFederationPost(w, r)
	if !ok {
		return
	}
	store := d.registry.Store()
	sealer := d.registry.Sealer()
	if store == nil || sealer == nil {
		http.Error(w, "federation infrastructure unavailable", http.StatusServiceUnavailable)
		return
	}
	if store.HasSealedNsec(npub) {
		http.Error(w, "watcher already configured for this npub", http.StatusConflict)
		return
	}

	nsec := strings.TrimSpace(r.FormValue("nsec"))
	if nsec == "" {
		http.Error(w, "nsec required", http.StatusBadRequest)
		return
	}
	prefix, data, err := nip19.Decode(nsec)
	if err != nil || prefix != "nsec" {
		http.Error(w, "invalid nsec", http.StatusBadRequest)
		return
	}
	skHex, isString := data.(string)
	if !isString || skHex == "" {
		http.Error(w, "invalid nsec payload", http.StatusBadRequest)
		return
	}
	pkHex, err := nostr.GetPublicKey(skHex)
	if err != nil {
		http.Error(w, "pubkey derivation failed", http.StatusBadRequest)
		return
	}

	if err := d.enrollWatcher(npub, skHex, pkHex); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// requireFederationPost enforces method=POST, federation mode, session
// auth, and CSRF on form POSTs. Returns pubkey, npub, and ok=false when
// it has already written an HTTP error response.
func (d *DeadManSwitch) requireFederationPost(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", "", false
	}
	if !d.cfg.FederationV1 {
		http.Error(w, "federation-only", http.StatusServiceUnavailable)
		return "", "", false
	}
	if d.registry == nil {
		http.Error(w, "registry unavailable", http.StatusServiceUnavailable)
		return "", "", false
	}
	pubkey := d.sessions.pubkeyFromRequest(r)
	if pubkey == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", "", false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return "", "", false
	}
	token := r.FormValue("csrf_token")
	if token == "" || !d.sessions.verifyCSRFToken(pubkey, token) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return "", "", false
	}
	npub, err := formatNpub(pubkey)
	if err != nil {
		http.Error(w, "bad session pubkey", http.StatusInternalServerError)
		return "", "", false
	}
	return pubkey, npub, true
}

// enrollWatcher is the shared persistence flow for generate and import:
// seal the sk, create the user dir, write the sealed blob, seed a
// UserConfig with sensible defaults, and start the watcher goroutine.
func (d *DeadManSwitch) enrollWatcher(npub, skHex, pkHex string) error {
	store := d.registry.Store()
	sealer := d.registry.Sealer()
	sealed, err := sealer.Seal(npub, []byte(skHex))
	if err != nil {
		return fmt.Errorf("sealing nsec: %w", err)
	}
	if err := store.CreateUser(npub); err != nil {
		return fmt.Errorf("creating user dir: %w", err)
	}
	if err := store.SaveSealedNsec(npub, sealed); err != nil {
		return fmt.Errorf("saving sealed nsec: %w", err)
	}
	uc := &UserConfig{
		SubjectNpub:      npub,
		WatcherPubkeyHex: pkHex,
		SilenceThreshold: Duration{30 * 24 * time.Hour},
		WarningInterval:  Duration{24 * time.Hour},
		WarningCount:     2,
		CheckInterval:    Duration{time.Hour},
		UpdatedAt:        time.Now(),
	}
	if err := store.SaveConfig(npub, uc); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	if err := d.registry.Start(npub); err != nil {
		return fmt.Errorf("starting watcher: %w", err)
	}
	return nil
}

type adminHubData struct {
	Npub          string
	FullNpub      string
	Status        string
	StatusLabel   string
	SilenceAge    string
	TimeRemaining string
	Threshold     string
	Progress      int
	WarningsSent  int
	WarningsMax   int
	LastSeen      string
	Relays        []RelayStatus
	Triggered     bool
	TriggeredAt   string
	Warnings      []configWarning
	StartedAt     string
}

// handleAdminFederation renders the per-user admin hub. If the user has
// no running watcher (either they skipped the bootstrap flow or their
// sealed nsec is missing), redirect them to /admin/watcher. Otherwise
// show a scoped view of their switch: timer, warnings, relays, and
// any per-user config warnings.
func (d *DeadManSwitch) handleAdminFederation(w http.ResponseWriter, r *http.Request) {
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

	watcher := d.registry.Get(npub)
	if watcher == nil {
		// Not running — either the user hasn't bootstrapped yet, or their
		// sealed nsec is missing and the factory failed. Either way, the
		// setup flow is the right next step.
		http.Redirect(w, r, "/admin/watcher", http.StatusSeeOther)
		return
	}

	uc := watcher.Config()
	if uc == nil {
		http.Redirect(w, r, "/admin/watcher", http.StatusSeeOther)
		return
	}
	snap := watcher.Snapshot()

	loc := d.cfg.location
	if loc == nil {
		loc = time.UTC
	}
	tfmt := "2006-01-02 15:04 MST"

	silence := time.Since(snap.LastSeen)
	data := adminHubData{
		Npub:         truncateMiddle(npub, 24),
		FullNpub:     npub,
		SilenceAge:   humanDuration(silence),
		Threshold:    humanDuration(uc.SilenceThreshold.Duration),
		WarningsSent: snap.WarningsSent,
		WarningsMax:  uc.WarningCount,
		Triggered:    snap.Triggered,
		Relays:       snap.RelayStatuses,
		StartedAt:    d.startedAt.In(loc).Format(tfmt),
	}
	if !snap.LastSeen.IsZero() {
		data.LastSeen = snap.LastSeen.In(loc).Format(tfmt)
	} else {
		data.LastSeen = "—"
	}
	if snap.TriggeredAt != nil {
		data.TriggeredAt = snap.TriggeredAt.In(loc).Format(tfmt)
	}

	totalTime := uc.SilenceThreshold.Duration + uc.WarningInterval.Duration*time.Duration(uc.WarningCount)
	if totalTime > 0 {
		data.Progress = int(silence * 100 / totalTime)
		if data.Progress > 100 {
			data.Progress = 100
		}
		if data.Progress < 0 {
			data.Progress = 0
		}
	}
	if rem := totalTime - silence; rem > 0 {
		data.TimeRemaining = humanDuration(rem)
	} else {
		data.TimeRemaining = "0"
	}

	data.Status = snapshotStatus(snap, uc)
	switch data.Status {
	case "healthy":
		data.StatusLabel = "Healthy"
	case "warning":
		data.StatusLabel = "Warning Sent"
	case "triggered":
		data.StatusLabel = "Triggered"
	}

	data.Warnings = userConfigWarnings(uc)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	adminHubTemplate.Execute(w, data)
}

// snapshotStatus mirrors *DeadManSwitch.currentStatus but works on a
// WatcherSnapshot + UserConfig pair, so the federation hub can label
// the user's switch without touching the legacy top-level state.
func snapshotStatus(snap WatcherSnapshot, uc *UserConfig) string {
	if snap.Triggered {
		return "triggered"
	}
	if snap.WarningsSent > 0 {
		return "warning"
	}
	if snap.LastSeen.IsZero() {
		return "healthy"
	}
	if time.Since(snap.LastSeen) > uc.SilenceThreshold.Duration {
		return "warning"
	}
	return "healthy"
}

// userConfigWarnings surfaces the per-user equivalents of
// *DeadManSwitch.configWarnings: empty action list plus per-action
// validation. Legacy-only checks (watch_pubkey, bot_nsec, relays)
// don't apply — federation UserConfigs can't express those.
func userConfigWarnings(uc *UserConfig) []configWarning {
	var out []configWarning
	if len(uc.Actions) == 0 {
		out = append(out, configWarning{
			Title:  "No trigger actions configured",
			Detail: "If the switch triggers, nothing will happen. Add at least one action at /admin/config.",
		})
	}
	out = append(out, actionWarnings(uc.Actions, "your config")...)
	return out
}

var adminHubTemplate = template.Must(template.New("adminHub").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin · Dead Man's Switch</title>
<style>
  :root {
    --bg:#0f1117; --card:#1a1d27; --border:#2a2d3a; --text:#e1e4ed; --muted:#6b7194;
    --green:#22c55e; --yellow:#eab308; --red:#ef4444; --accent:#a78bfa;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; padding:2rem 1rem; display:flex; justify-content:center; }
  .container { max-width:480px; width:100%; }
  h1 { font-size:1.25rem; font-weight:600; margin-bottom:1.25rem; display:flex; align-items:center; gap:0.5rem; }
  .status-badge { display:inline-flex; align-items:center; gap:0.375rem; padding:0.25rem 0.75rem; border-radius:9999px; font-size:0.8rem; font-weight:500; }
  .status-dot { width:8px; height:8px; border-radius:50%; }
  .status-healthy .status-dot { background:var(--green); box-shadow:0 0 8px var(--green); }
  .status-healthy { background:rgba(34,197,94,0.1); color:var(--green); }
  .status-warning .status-dot { background:var(--yellow); box-shadow:0 0 8px var(--yellow); }
  .status-warning { background:rgba(234,179,8,0.1); color:var(--yellow); }
  .status-triggered .status-dot { background:var(--red); box-shadow:0 0 8px var(--red); }
  .status-triggered { background:rgba(239,68,68,0.1); color:var(--red); }
  .npub { margin-left:auto; font-family:monospace; font-size:0.75rem; color:var(--muted); font-weight:400; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:0.75rem; padding:1.25rem; margin-bottom:1rem; }
  .card-title { font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:0.75rem; }
  .stat-grid { display:grid; grid-template-columns:1fr 1fr; gap:1rem; }
  .stat-label { font-size:0.75rem; color:var(--muted); margin-bottom:0.125rem; }
  .stat-value { font-size:1.1rem; font-weight:600; font-variant-numeric:tabular-nums; }
  .stat-value.large { font-size:1.5rem; }
  .progress-track { height:6px; background:var(--border); border-radius:3px; margin-top:0.75rem; overflow:hidden; }
  .progress-bar { height:100%; border-radius:3px; transition:width 1s ease; }
  .progress-healthy { background:var(--green); }
  .progress-warning { background:var(--yellow); }
  .progress-triggered { background:var(--red); }
  .meta { font-size:0.75rem; color:var(--muted); display:flex; justify-content:space-between; margin-top:0.5rem; }
  .relay-row { display:flex; align-items:center; gap:0.5rem; margin-bottom:0.375rem; }
  .relay-dot { width:7px; height:7px; border-radius:50%; flex-shrink:0; }
  .relay-url { font-size:0.8rem; color:var(--muted); font-family:monospace; }
  .warn-card { background:rgba(234,179,8,0.08); border-color:rgba(234,179,8,0.4); }
  .warn-card .card-title { color:var(--yellow); }
  .warn-row { padding:0.5rem 0; border-bottom:1px solid rgba(234,179,8,0.15); }
  .warn-row:last-child { border-bottom:none; }
  .warn-title { font-size:0.85rem; font-weight:600; color:var(--yellow); margin-bottom:0.2rem; }
  .warn-detail { font-size:0.75rem; color:var(--muted); line-height:1.4; }
  .actions { display:flex; gap:0.5rem; margin-top:1rem; }
  a.btn, .actions form button { flex:1; padding:0.6rem 0.75rem; border-radius:0.5rem; border:1px solid var(--border); background:transparent; color:var(--text); text-decoration:none; text-align:center; font-size:0.85rem; cursor:pointer; font-family:inherit; font-weight:400; }
  a.btn:hover, .actions form button:hover { border-color:var(--accent); color:var(--accent); }
  .actions form { flex:1; margin:0; }
  .actions form button { width:100%; }
  .footer { text-align:center; font-size:0.7rem; color:var(--muted); margin-top:1rem; }
  .footer a { color:var(--muted); }
</style>
</head>
<body>
<div class="container">
  <h1>
    Admin
    <span class="status-badge status-{{.Status}}"><span class="status-dot"></span>{{.StatusLabel}}</span>
    <span class="npub">{{.Npub}}</span>
  </h1>

  {{if .Warnings}}
  <div class="card warn-card">
    <div class="card-title">Configuration Issues ({{len .Warnings}})</div>
    {{range .Warnings}}
    <div class="warn-row">
      <div class="warn-title">{{.Title}}</div>
      <div class="warn-detail">{{.Detail}}</div>
    </div>
    {{end}}
  </div>
  {{end}}

  <div class="card">
    <div class="card-title">Timer</div>
    <div class="stat-grid">
      <div>
        <div class="stat-label">Silent for</div>
        <div class="stat-value large">{{.SilenceAge}}</div>
      </div>
      <div>
        <div class="stat-label">Trigger in</div>
        <div class="stat-value large">{{.TimeRemaining}}</div>
      </div>
    </div>
    <div class="progress-track"><div class="progress-bar progress-{{.Status}}" style="width: {{.Progress}}%"></div></div>
    <div class="meta">
      <span>Threshold: {{.Threshold}}</span>
      <span>Warnings: {{.WarningsSent}}/{{.WarningsMax}}</span>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Activity</div>
    <div class="stat-label">Last seen</div>
    <div class="stat-value" style="margin-bottom:1rem">{{.LastSeen}}</div>
    <div class="stat-label" style="margin-bottom:0.5rem">Relays</div>
    {{range .Relays}}
    <div class="relay-row">
      <span class="relay-dot" style="background:{{if .Connected}}var(--green){{else}}var(--red){{end}};box-shadow:0 0 6px {{if .Connected}}var(--green){{else}}var(--red){{end}};"></span>
      <span class="relay-url">{{.URL}}</span>
    </div>
    {{end}}
  </div>

  {{if .Triggered}}
  <div class="card" style="border-color: var(--red);">
    <div class="card-title" style="color: var(--red);">Triggered</div>
    <div class="stat-label">Activated at</div>
    <div class="stat-value">{{.TriggeredAt}}</div>
    <div class="meta"><span>Contact the operator to re-arm</span></div>
  </div>
  {{end}}

  <div class="actions">
    <a class="btn" href="/admin/config">Configuration</a>
    <a class="btn" href="/">Status</a>
    <form method="POST" action="/logout"><button type="submit">Sign out</button></form>
  </div>

  <div class="footer">Running since {{.StartedAt}}</div>
</div>
<script>setTimeout(()=>location.reload(), 60000)</script>
</body>
</html>`))

var watcherSetupTemplate = template.Must(template.New("watcherSetup").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Set up watcher · Dead Man's Switch</title>
<style>
  :root { --bg:#0f1117; --card:#1a1d27; --border:#2a2d3a; --text:#e1e4ed; --muted:#6b7194; --accent:#a78bfa; --red:#ef4444; --green:#22c55e; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; padding:2rem 1rem; display:flex; justify-content:center; }
  .container { max-width:640px; width:100%; }
  h1 { font-size:1.25rem; font-weight:600; margin-bottom:0.35rem; display:flex; justify-content:space-between; align-items:center; gap:0.75rem; }
  .npub { font-family:monospace; font-size:0.8rem; color:var(--muted); font-weight:400; }
  .lead { color:var(--muted); font-size:0.9rem; line-height:1.5; margin-bottom:1.5rem; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:0.75rem; padding:1.25rem; margin-bottom:1rem; }
  .card-title { font-size:0.85rem; font-weight:600; margin-bottom:0.5rem; color:var(--text); }
  .muted { color:var(--muted); font-size:0.85rem; line-height:1.5; margin-bottom:0.75rem; }
  label.consent { display:flex; gap:0.5rem; align-items:flex-start; font-size:0.8rem; color:var(--muted); margin:0.75rem 0; line-height:1.4; }
  label.consent input { margin-top:0.2rem; }
  textarea { width:100%; min-height:96px; padding:0.6rem; background:var(--bg); border:1px solid var(--border); border-radius:0.5rem; color:var(--text); font-family:monospace; font-size:0.8rem; line-height:1.4; resize:vertical; }
  textarea:focus { outline:none; border-color:var(--accent); }
  button.primary { padding:0.6rem 1rem; border-radius:0.5rem; border:1px solid var(--accent); background:var(--accent); color:#0f1117; font-size:0.9rem; font-weight:600; cursor:pointer; font-family:inherit; width:100%; }
  button.primary:hover { filter:brightness(1.1); }
  button.ghost { padding:0.55rem 0.9rem; border-radius:0.5rem; border:1px solid var(--accent); background:transparent; color:var(--accent); font-size:0.85rem; cursor:pointer; font-family:inherit; }
  button.ghost:hover { background:var(--accent); color:#0f1117; }
  button.ghost:disabled { opacity:0.55; cursor:progress; }
  .warn-banner { background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.35); color:var(--red); padding:0.75rem 1rem; border-radius:0.5rem; font-size:0.85rem; margin-bottom:1.25rem; line-height:1.5; }
  .actions { display:flex; gap:0.5rem; margin-top:1rem; }
  a.btn { flex:1; padding:0.6rem 0.75rem; border-radius:0.5rem; border:1px solid var(--border); background:transparent; color:var(--text); text-decoration:none; text-align:center; font-size:0.85rem; }
  a.btn:hover { border-color:var(--accent); color:var(--accent); }
  .pub { font-family:monospace; font-size:0.8rem; color:var(--text); word-break:break-all; background:var(--bg); border:1px solid var(--border); border-radius:0.5rem; padding:0.6rem; user-select:all; }
  .reveal-row { display:flex; gap:0.5rem; flex-wrap:wrap; margin-top:0.75rem; }
  pre.secret { background:var(--bg); border:1px solid var(--red); border-radius:0.5rem; padding:0.75rem; margin-top:0.75rem; font-family:monospace; font-size:0.8rem; word-break:break-all; white-space:pre-wrap; user-select:all; color:var(--text); display:none; }
  pre.secret.shown { display:block; }
  .reveal-err { color:var(--red); font-size:0.8rem; margin-top:0.5rem; display:none; }
  .reveal-err.shown { display:block; }
</style>
</head>
<body>
<div class="container">
  <h1>
    Watcher setup
    <span class="npub">{{.Npub}}</span>
  </h1>
  {{if .AlreadySetup}}
  <div class="card">
    <div class="card-title">Watcher pubkey (safe to share)</div>
    <div class="muted">
      This is the bot that will sign warning DMs and the final trigger event. Follow or subscribe to this npub in your Nostr client so its DMs and notes actually reach you.
    </div>
    {{if .WatcherNpub}}
    <div class="pub" id="watcher-npub">{{.WatcherNpub}}</div>
    <div class="reveal-row">
      <button type="button" class="ghost" onclick="copyWatcherNpub()">Copy npub</button>
    </div>
    {{else}}
    <div class="muted">Watcher pubkey unavailable — your config may not have finished seeding. Try again in a moment.</div>
    {{end}}
  </div>
  <div class="card">
    <div class="card-title">Reveal watcher nsec</div>
    <div class="muted">
      Export the sealed bot key as an nsec — useful if you want to mirror this watcher on another service or back it up offline. You'll need to sign a fresh challenge with your Nostr extension to confirm it's really you.
    </div>
    <div class="reveal-row">
      <button type="button" id="reveal-btn" class="ghost" data-csrf="{{.CSRF}}">Reveal nsec</button>
      <button type="button" id="reveal-copy" class="ghost" style="display:none" onclick="copyRevealed()">Copy nsec</button>
    </div>
    <pre class="secret" id="reveal-out"></pre>
    <div class="reveal-err" id="reveal-err"></div>
  </div>
  <div class="actions">
    <a class="btn" href="/admin">Go to admin</a>
    <a class="btn" href="/admin/config">Configuration</a>
  </div>
  {{else}}
  <p class="lead">
    Before your switch can monitor you, it needs a bot key that will sign warning DMs and the final triggered event. Generate a new one in-browser or paste an existing nsec.
  </p>
  <div class="warn-banner">
    <strong>Heads up.</strong> A generated nsec is displayed exactly once. Copy it into a password manager before leaving the next screen — we cannot recover it.
  </div>
  <div class="card">
    <div class="card-title">Generate a new bot key</div>
    <div class="muted">Creates a fresh nsec and shows it once. After that it's sealed at rest with the server's store key.</div>
    <form method="POST" action="/admin/watcher/generate">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <label class="consent"><input type="checkbox" required> I understand this nsec will be shown once and cannot be recovered.</label>
      <button type="submit" class="primary">Generate</button>
    </form>
  </div>
  <div class="card">
    <div class="card-title">Import an existing nsec</div>
    <div class="muted">Useful if you already have a bot key or are migrating from another host.</div>
    <form method="POST" action="/admin/watcher/import">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <textarea name="nsec" placeholder="nsec1..." required spellcheck="false"></textarea>
      <div style="margin-top:0.75rem">
        <button type="submit" class="primary">Import</button>
      </div>
    </form>
  </div>
  {{end}}
  <div class="actions">
    <a class="btn" href="/">Status</a>
    <form method="POST" action="/logout" style="flex:1;margin:0"><button type="submit" class="btn" style="width:100%;cursor:pointer;font-family:inherit">Sign out</button></form>
  </div>
</div>
{{if .AlreadySetup}}
<script>
function copyWatcherNpub(){
  const el = document.getElementById('watcher-npub');
  if (!el) return;
  navigator.clipboard.writeText(el.textContent.trim()).catch(()=>{
    const r = document.createRange(); r.selectNode(el);
    window.getSelection().removeAllRanges(); window.getSelection().addRange(r);
  });
}
function copyRevealed(){
  const el = document.getElementById('reveal-out');
  if (!el || !el.textContent) return;
  navigator.clipboard.writeText(el.textContent.trim()).catch(()=>{
    const r = document.createRange(); r.selectNode(el);
    window.getSelection().removeAllRanges(); window.getSelection().addRange(r);
  });
}
(function(){
  const btn = document.getElementById('reveal-btn');
  if (!btn) return;
  const out = document.getElementById('reveal-out');
  const errEl = document.getElementById('reveal-err');
  const copyBtn = document.getElementById('reveal-copy');
  function showErr(msg){ errEl.textContent = msg; errEl.classList.add('shown'); btn.disabled = false; btn.textContent = 'Reveal nsec'; }
  btn.addEventListener('click', async () => {
    errEl.classList.remove('shown'); out.classList.remove('shown'); out.textContent = '';
    copyBtn.style.display = 'none';
    if (typeof window.nostr === 'undefined') { showErr('No Nostr extension detected in this browser.'); return; }
    btn.disabled = true; btn.textContent = 'Signing…';
    try {
      const cr = await fetch('/admin/watcher/reveal/challenge');
      if (!cr.ok) throw new Error('Failed to get challenge');
      const { challenge } = await cr.json();
      const signed = await window.nostr.signEvent({
        kind: 22242,
        created_at: Math.floor(Date.now()/1000),
        tags: [['challenge', challenge]],
        content: 'Reveal watcher nsec'
      });
      const vr = await fetch('/admin/watcher/reveal', {
        method: 'POST',
        headers: {'Content-Type':'application/json', 'X-CSRF-Token': btn.dataset.csrf},
        body: JSON.stringify({ signedEvent: signed })
      });
      if (!vr.ok) { const t = await vr.text(); throw new Error(t || 'Reveal failed'); }
      const { nsec } = await vr.json();
      out.textContent = nsec;
      out.classList.add('shown');
      copyBtn.style.display = '';
      btn.disabled = false; btn.textContent = 'Reveal nsec';
    } catch (e) {
      showErr(e.message || String(e));
    }
  });
})();
</script>
{{end}}
</body>
</html>`))

var watcherGeneratedTemplate = template.Must(template.New("watcherGenerated").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Save your nsec · Dead Man's Switch</title>
<style>
  :root { --bg:#0f1117; --card:#1a1d27; --border:#2a2d3a; --text:#e1e4ed; --muted:#6b7194; --accent:#a78bfa; --red:#ef4444; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; padding:2rem 1rem; display:flex; justify-content:center; }
  .container { max-width:640px; width:100%; }
  h1 { font-size:1.25rem; font-weight:600; margin-bottom:0.35rem; }
  .warn-banner { background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.45); color:var(--red); padding:0.9rem 1rem; border-radius:0.5rem; font-size:0.9rem; margin-bottom:1.25rem; line-height:1.55; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:0.75rem; padding:1.25rem; margin-bottom:1rem; }
  .card-title { font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:0.5rem; }
  pre.secret { background:var(--bg); border:1px solid var(--border); border-radius:0.5rem; padding:0.9rem; font-family:monospace; font-size:0.85rem; word-break:break-all; white-space:pre-wrap; user-select:all; }
  .pub { font-family:monospace; font-size:0.8rem; color:var(--muted); word-break:break-all; }
  button.copy { margin-top:0.75rem; padding:0.5rem 0.9rem; border-radius:0.5rem; border:1px solid var(--accent); background:transparent; color:var(--accent); font-size:0.85rem; cursor:pointer; font-family:inherit; }
  button.copy:hover { background:var(--accent); color:#0f1117; }
  .actions { display:flex; gap:0.5rem; margin-top:1rem; }
  a.primary { flex:1; padding:0.7rem 1rem; border-radius:0.5rem; border:1px solid var(--accent); background:var(--accent); color:#0f1117; text-decoration:none; text-align:center; font-size:0.9rem; font-weight:600; }
  a.primary:hover { filter:brightness(1.1); }
</style>
</head>
<body>
<div class="container">
  <h1>Your new bot nsec</h1>
  <div class="warn-banner">
    <strong>Copy this now.</strong> This is the only time we will show your nsec. Paste it into a password manager before clicking continue. If you lose it you'll need to rotate the watcher key.
  </div>
  <div class="card">
    <div class="card-title">Private key (nsec)</div>
    <pre class="secret" id="nsec">{{.Nsec}}</pre>
    <button class="copy" type="button" onclick="copyNsec()">Copy to clipboard</button>
  </div>
  <div class="card">
    <div class="card-title">Bot pubkey (safe to share)</div>
    <div class="pub">{{.Pubnpub}}</div>
  </div>
  <div class="actions">
    <a href="/admin" class="primary">I've saved it — continue</a>
  </div>
</div>
<script>
function copyNsec(){
  const el = document.getElementById('nsec');
  navigator.clipboard.writeText(el.textContent).catch(()=>{
    const r = document.createRange(); r.selectNode(el);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
  });
}
</script>
</body>
</html>`))

type adminConfigData struct {
	Npub       string
	FullNpub   string
	CSRF       string
	Initial    template.JS
	HostRelays template.JS
}

// handleAdminConfigGet renders the federation per-user config editor.
// Unauthenticated / wrong-mode handling is the same as handleAdminFederation:
// no watcher ⇒ redirect to /admin/watcher so the user bootstraps first.
func (d *DeadManSwitch) handleAdminConfigGet(w http.ResponseWriter, r *http.Request) {
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
	watcher := d.registry.Get(npub)
	if watcher == nil {
		http.Redirect(w, r, "/admin/watcher", http.StatusSeeOther)
		return
	}
	uc := watcher.Config()
	if uc == nil {
		http.Redirect(w, r, "/admin/watcher", http.StatusSeeOther)
		return
	}

	initialBytes, err := json.Marshal(uc)
	if err != nil {
		http.Error(w, "encoding config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var hostRelays []string
	if host := d.registry.Host(); host != nil {
		hostRelays = host.Relays
	}
	hostBytes, _ := json.Marshal(hostRelays)

	data := adminConfigData{
		Npub:       truncateMiddle(npub, 24),
		FullNpub:   npub,
		CSRF:       d.sessions.issueCSRFToken(pubkey),
		Initial:    template.JS(initialBytes),
		HostRelays: template.JS(hostBytes),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	adminConfigTemplate.Execute(w, data)
}

type testActionRequest struct {
	Type   string         `json:"type"`
	Config map[string]any `json:"config"`
	Index  int            `json:"index"`
}

type testActionResponse struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// handleAdminConfigTestAction fires a single action once and reports the
// result inline. Federation-mode only, CSRF-required, per-pubkey cooldown.
// On executor failure the response is HTTP 200 with {ok:false,error:...}
// so the client can render the message inline; 4xx/5xx codes are reserved
// for structural problems (bad JSON, missing session, etc).
func (d *DeadManSwitch) handleAdminConfigTestAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !d.cfg.FederationV1 {
		http.Error(w, "federation-only", http.StatusServiceUnavailable)
		return
	}
	pubkey := d.sessions.pubkeyFromRequest(r)
	if pubkey == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if token := r.Header.Get("X-CSRF-Token"); token == "" || !d.sessions.verifyCSRFToken(pubkey, token) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	if !d.testAction.Allow(pubkey, time.Now()) {
		http.Error(w, "rate limited; wait a moment and try again", http.StatusTooManyRequests)
		return
	}
	npub, err := formatNpub(pubkey)
	if err != nil {
		http.Error(w, "bad session pubkey", http.StatusInternalServerError)
		return
	}
	if d.registry == nil {
		http.Error(w, "registry unavailable", http.StatusServiceUnavailable)
		return
	}
	watcher := d.registry.Get(npub)
	if watcher == nil {
		http.Error(w, "no watcher running for your npub", http.StatusNotFound)
		return
	}

	var body testActionRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, adminConfigMaxBytes))
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Config == nil {
		body.Config = map[string]any{}
	}

	stored := watcher.Config()
	if stored != nil && body.Index >= 0 && body.Index < len(stored.Actions) {
		mergeSecretMap(body.Config, stored.Actions[body.Index].Config)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	host := d.registry.Host()
	exec := d.execActionFn
	if exec == nil {
		exec = executeAction
	}
	err = exec(ctx, body.Type, body.Config, host, stored,
		watcher.WatcherPrivHex(), watcher.WatcherPubHex())

	w.Header().Set("Content-Type", "application/json")
	resp := testActionResponse{Ok: err == nil}
	if err != nil {
		resp.Error = err.Error()
	}
	json.NewEncoder(w).Encode(resp)
}

// mergeSecretMasks walks new's actions and, wherever a known-secret field
// holds the maskedDisplay placeholder, substitutes the corresponding value
// from old. This lets the UI render secrets as bullets while still round-
// tripping them on save without the user having to re-type them.
func mergeSecretMasks(newCfg, oldCfg *UserConfig) {
	if oldCfg == nil {
		return
	}
	for i := range newCfg.Actions {
		if i >= len(oldCfg.Actions) {
			continue
		}
		mergeSecretMap(newCfg.Actions[i].Config, oldCfg.Actions[i].Config)
	}
}

func mergeSecretMap(dst, src map[string]any) {
	if dst == nil || src == nil {
		return
	}
	for k, v := range dst {
		switch vv := v.(type) {
		case string:
			if vv == maskedDisplay && isSecretKey(k) {
				if oldV, ok := src[k]; ok {
					dst[k] = oldV
				} else {
					delete(dst, k)
				}
			}
		case map[string]any:
			if sm, ok := src[k].(map[string]any); ok {
				mergeSecretMap(vv, sm)
			}
		}
	}
}

var adminConfigTemplate = template.Must(template.New("adminConfig").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Configuration · Dead Man's Switch</title>
<style>
  :root { --bg:#0f1117; --card:#1a1d27; --border:#2a2d3a; --text:#e1e4ed; --muted:#6b7194; --accent:#a78bfa; --red:#ef4444; --green:#22c55e; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; padding:2rem 1rem; display:flex; justify-content:center; }
  .container { max-width:720px; width:100%; }
  h1 { font-size:1.25rem; font-weight:600; margin-bottom:1.25rem; display:flex; justify-content:space-between; align-items:center; gap:0.75rem; }
  h2 { font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:0.75rem; font-weight:500; }
  .npub { font-family:monospace; font-size:0.8rem; color:var(--muted); font-weight:400; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:0.75rem; padding:1.25rem; margin-bottom:1rem; }
  .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:0.75rem; }
  label { display:block; font-size:0.75rem; color:var(--muted); margin-bottom:0.75rem; }
  label span.k { display:block; margin-bottom:0.25rem; }
  input[type="text"], input[type="number"], input[type="password"], input:not([type]), textarea, select {
    width:100%; padding:0.55rem 0.65rem; background:var(--bg); border:1px solid var(--border);
    border-radius:0.4rem; color:var(--text); font-family:inherit; font-size:0.85rem;
  }
  textarea { font-family:monospace; font-size:0.8rem; min-height:80px; resize:vertical; line-height:1.4; }
  input:focus, textarea:focus, select:focus { outline:none; border-color:var(--accent); }
  .muted { color:var(--muted); font-size:0.8rem; line-height:1.5; margin-bottom:0.75rem; }
  button { padding:0.55rem 0.9rem; border-radius:0.4rem; border:1px solid var(--accent); background:var(--accent); color:#0f1117; font-size:0.85rem; font-weight:600; cursor:pointer; font-family:inherit; }
  button:hover { filter:brightness(1.1); }
  button.secondary { background:transparent; color:var(--text); border:1px solid var(--border); font-weight:400; }
  button.secondary:hover { border-color:var(--accent); color:var(--accent); }
  button.danger { background:transparent; color:var(--red); border:1px solid rgba(239,68,68,0.4); font-weight:400; }
  button.danger:hover { background:rgba(239,68,68,0.1); }
  .action { border:1px solid var(--border); border-radius:0.5rem; padding:0.9rem; margin-bottom:0.75rem; background:rgba(15,17,23,0.35); }
  .action-head { display:flex; align-items:center; gap:0.75rem; margin-bottom:0.75rem; }
  .action-head .action-index { font-size:0.75rem; color:var(--muted); text-transform:uppercase; letter-spacing:0.05em; }
  .action-head .spacer { flex:1; }
  .type-fields { display:none; }
  .msg { font-size:0.85rem; padding:0.6rem 0.75rem; border-radius:0.4rem; margin-bottom:1rem; display:none; white-space:pre-wrap; }
  .msg.err { display:block; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.4); color:var(--red); }
  .msg.ok { display:block; background:rgba(34,197,94,0.1); border:1px solid rgba(34,197,94,0.4); color:var(--green); }
  .card-actions { display:flex; gap:0.5rem; align-items:center; }
  .dur { display:flex; gap:0.4rem; align-items:stretch; }
  .dur .dur-n { flex:1; min-width:0; }
  .dur .dur-u { flex:0 0 auto; width:auto; }
  .dur .dur-raw { flex:1; }
  .dur-toggle { background:none; border:none; color:var(--muted); font-size:0.7rem; cursor:pointer; padding:0.2rem 0; margin-top:0.15rem; font-family:inherit; }
  .dur-toggle:hover { color:var(--accent); }
  details { background:var(--card); border:1px solid var(--border); border-radius:0.75rem; padding:1rem 1.25rem; margin-bottom:1rem; }
  details > summary { cursor:pointer; font-size:0.85rem; color:var(--muted); }
  details[open] > summary { margin-bottom:0.75rem; color:var(--text); }
  #raw-json { min-height:280px; font-size:0.8rem; }
  .footer-actions { display:flex; gap:0.5rem; margin-top:1rem; }
  .footer-actions a, .footer-actions form { flex:1; }
  .footer-actions a, .footer-actions form button { width:100%; padding:0.6rem 0.75rem; border-radius:0.5rem; border:1px solid var(--border); background:transparent; color:var(--text); text-decoration:none; text-align:center; font-size:0.85rem; cursor:pointer; font-family:inherit; font-weight:400; display:block; }
  .footer-actions a:hover, .footer-actions form button:hover { border-color:var(--accent); color:var(--accent); }
  .footer-actions form { margin:0; }
</style>
</head>
<body>
<div class="container">
  <h1>Configuration <span class="npub">{{.Npub}}</span></h1>
  <div id="msg" class="msg"></div>

  <div class="card">
    <h2>Timer</h2>
    <div class="grid-2">
      <label>
        <span class="k">Silence threshold</span>
        <div class="dur" data-k="silence_threshold">
          <input class="dur-n" type="number" min="1" step="1">
          <select class="dur-u">
            <option value="m">minutes</option>
            <option value="h">hours</option>
            <option value="d">days</option>
            <option value="w">weeks</option>
          </select>
          <input class="dur-raw" type="text" placeholder="e.g. 1h30m" hidden>
        </div>
        <button type="button" class="dur-toggle" data-for="silence_threshold">Use raw duration</button>
      </label>
      <label>
        <span class="k">Warning interval</span>
        <div class="dur" data-k="warning_interval">
          <input class="dur-n" type="number" min="1" step="1">
          <select class="dur-u">
            <option value="m">minutes</option>
            <option value="h">hours</option>
            <option value="d">days</option>
            <option value="w">weeks</option>
          </select>
          <input class="dur-raw" type="text" placeholder="e.g. 1h30m" hidden>
        </div>
        <button type="button" class="dur-toggle" data-for="warning_interval">Use raw duration</button>
      </label>
      <label><span class="k">Warning count</span><input id="warning_count" type="number" min="0"></label>
      <label>
        <span class="k">Check interval</span>
        <div class="dur" data-k="check_interval">
          <input class="dur-n" type="number" min="1" step="1">
          <select class="dur-u">
            <option value="m">minutes</option>
            <option value="h">hours</option>
            <option value="d">days</option>
            <option value="w">weeks</option>
          </select>
          <input class="dur-raw" type="text" placeholder="e.g. 1h30m" hidden>
        </div>
        <button type="button" class="dur-toggle" data-for="check_interval">Use raw duration</button>
      </label>
    </div>
  </div>

  <div class="card">
    <h2>Relays</h2>
    <div class="muted">One wss:// URL per line. Leave empty to inherit the host's relays.</div>
    <textarea id="relays" spellcheck="false"></textarea>
    <div style="margin-top:0.5rem"><button type="button" class="secondary" id="relays-defaults">Reset to host defaults</button></div>
  </div>

  <div class="card">
    <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.75rem">
      <h2 style="margin:0">Actions</h2>
      <div style="flex:1"></div>
      <button type="button" class="secondary" id="add-action">+ Add action</button>
    </div>
    <div id="actions-list"></div>
  </div>

  <details>
    <summary>Show raw JSON (fallback / power user)</summary>
    <div class="muted">Edits here take precedence over the form fields above when you press Save.</div>
    <textarea id="raw-json" spellcheck="false"></textarea>
  </details>

  <div class="card card-actions">
    <button type="button" id="save">Save</button>
    <span class="muted" style="margin:0">Signs as a self-DM and propagates to peer instances.</span>
  </div>

  <div class="footer-actions">
    <a href="/admin">Back to admin</a>
    <form method="POST" action="/logout"><button type="submit">Sign out</button></form>
  </div>

  <template id="action-template">
    <div class="action">
      <div class="action-head">
        <span class="action-index">Action</span>
        <select class="action-type">
          <option value="email">Email</option>
          <option value="webhook">Webhook</option>
          <option value="nostr_note">Nostr note</option>
          <option value="nostr_dm">Nostr DM</option>
          <option value="nostr_event">Nostr event</option>
        </select>
        <div class="spacer"></div>
        <button type="button" class="secondary action-test">Test</button>
        <button type="button" class="danger action-remove">Remove</button>
      </div>
      <div class="action-msg msg"></div>
      <div class="type-fields type-email">
        <div class="grid-2">
          <label><span class="k">SMTP host</span><input data-k="smtp_host" placeholder="smtp.fastmail.com"></label>
          <label><span class="k">SMTP port</span><input data-k="smtp_port" type="number" placeholder="587"></label>
          <label><span class="k">SMTP user</span><input data-k="smtp_user" placeholder="you@example.com"></label>
          <label><span class="k">SMTP password</span><input data-k="smtp_pass" type="text" placeholder="••••••••"></label>
          <label>
            <span class="k">From</span>
            <input data-k="from" placeholder="alerts@example.com">
            <div class="muted" style="margin:0.2rem 0 0;font-size:0.7rem">Defaults to SMTP user if blank.</div>
          </label>
          <label><span class="k">To</span><input data-k="to" placeholder="recipient@example.com"></label>
        </div>
        <label><span class="k">Subject</span><input data-k="subject" placeholder="Dead man's switch triggered"></label>
        <label><span class="k">Body</span><textarea data-k="body" placeholder="If you got this, I haven't posted on nostr in a while."></textarea></label>
      </div>
      <div class="type-fields type-webhook">
        <label><span class="k">URL</span><input data-k="url" placeholder="https://example.com/notify"></label>
        <label><span class="k">Method</span>
          <select data-k="method"><option value="POST">POST</option><option value="GET">GET</option></select>
        </label>
        <label><span class="k">Body</span><textarea data-k="body" placeholder='{"event":"triggered"}'></textarea></label>
      </div>
      <div class="type-fields type-nostr_note">
        <label><span class="k">Content</span><textarea data-k="content" placeholder="If you're reading this, I'm overdue. Here's what I wanted known…"></textarea></label>
      </div>
      <div class="type-fields type-nostr_dm">
        <label>
          <span class="k">Recipient npub</span>
          <input data-k="to_npub" placeholder="npub1…">
          <div class="muted" style="margin:0.2rem 0 0;font-size:0.7rem">NIP-04 encrypted DM from your watcher to this npub.</div>
        </label>
        <label><span class="k">Content</span><textarea data-k="content" placeholder="Private message for this recipient only."></textarea></label>
      </div>
      <div class="type-fields type-nostr_event">
        <label>
          <span class="k">Signed event JSON</span>
          <textarea data-k="event_json" placeholder='{"id":"...","sig":"...","pubkey":"...","kind":1,"content":"...","tags":[],"created_at":0}'></textarea>
          <div class="muted" style="margin:0.2rem 0 0;font-size:0.7rem">Pre-sign with <code>nak event --sec nsec1…</code> and paste the full JSON here.</div>
        </label>
        <label><span class="k">Relays (comma-separated, optional)</span><input data-k="relays" placeholder="wss://relay.damus.io, wss://nos.lol"></label>
      </div>
    </div>
  </template>
</div>
<script>
  const csrf = "{{.CSRF}}";
  const subjectNpub = "{{.FullNpub}}";
  const initial = {{.Initial}};
  const hostRelays = {{.HostRelays}};
  const MASK = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
  const SECRET_RE = /pass|passwd|password|token|secret|nsec|privkey|apikey|api_key/i;

  function $(id) { return document.getElementById(id); }
  function showMsg(cls, text) { const el = $('msg'); el.className = 'msg ' + cls; el.textContent = text; }

  function durWrap(key) { return document.querySelector('.dur[data-k="' + key + '"]'); }

  // parseGoToMinutes returns the total minutes represented by a Go duration
  // string like "720h0m0s". Returns null if s has fractional minutes (sub-
  // minute precision) or fails to parse.
  function parseGoToMinutes(s) {
    if (!s) return null;
    const re = /(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g;
    const mult = { ns: 1/60e9, us: 1/60e6, 'µs': 1/60e6, ms: 1/60e3, s: 1/60, m: 1, h: 60 };
    let total = 0, matched = false, m;
    while ((m = re.exec(s)) !== null) {
      matched = true;
      total += parseFloat(m[1]) * mult[m[2]];
    }
    if (!matched) return null;
    if (Math.abs(total - Math.round(total)) > 1e-9) return null;
    return Math.round(total);
  }

  function bestUnit(minutes) {
    if (minutes <= 0) return null;
    if (minutes % 10080 === 0) return { n: minutes / 10080, u: 'w' };
    if (minutes % 1440 === 0) return { n: minutes / 1440, u: 'd' };
    if (minutes % 60 === 0) return { n: minutes / 60, u: 'h' };
    return { n: minutes, u: 'm' };
  }

  function setDurMode(wrap, mode) {
    wrap.dataset.mode = mode;
    const showUnit = mode === 'unit';
    wrap.querySelector('.dur-n').hidden = !showUnit;
    wrap.querySelector('.dur-u').hidden = !showUnit;
    wrap.querySelector('.dur-raw').hidden = showUnit;
    const toggle = document.querySelector('.dur-toggle[data-for="' + wrap.dataset.k + '"]');
    if (toggle) toggle.textContent = showUnit ? 'Use raw duration' : 'Use picker';
  }

  function setDur(key, s) {
    const wrap = durWrap(key);
    if (!wrap) return;
    const minutes = parseGoToMinutes(s);
    const best = minutes != null ? bestUnit(minutes) : null;
    if (best) {
      wrap.querySelector('.dur-n').value = best.n;
      wrap.querySelector('.dur-u').value = best.u;
      wrap.querySelector('.dur-raw').value = '';
      setDurMode(wrap, 'unit');
    } else {
      wrap.querySelector('.dur-raw').value = s || '';
      setDurMode(wrap, 'raw');
    }
  }

  function getDur(key) {
    const wrap = durWrap(key);
    if (!wrap) return '';
    if (wrap.dataset.mode === 'raw') {
      return wrap.querySelector('.dur-raw').value.trim();
    }
    const n = wrap.querySelector('.dur-n').value.trim();
    const u = wrap.querySelector('.dur-u').value;
    if (!n) return '';
    return n + u;
  }

  function hydrate(uc) {
    setDur('silence_threshold', uc.silence_threshold || '');
    setDur('warning_interval', uc.warning_interval || '');
    $('warning_count').value = (uc.warning_count != null) ? uc.warning_count : 2;
    setDur('check_interval', uc.check_interval || '');
    $('relays').value = (uc.relays || []).join('\n');
    const list = $('actions-list');
    list.innerHTML = '';
    (uc.actions || []).forEach(a => addAction(a));
  }

  // actionDefaults seeds a freshly-added action with non-blank sensibles.
  // Only applied when the caller passes an empty config (i.e. the + Add
  // action button); hydrated-from-server actions pass through untouched.
  const ACTION_DEFAULTS = {
    email: { smtp_port: 587 },
    webhook: { method: 'POST' },
    nostr_note: {},
    nostr_dm: {},
    nostr_event: {},
  };

  function addAction(a) {
    const tpl = $('action-template').content.firstElementChild.cloneNode(true);
    const sel = tpl.querySelector('.action-type');
    const type = a && a.type ? a.type : 'email';
    sel.value = type;
    updateTypeVisibility(tpl);
    sel.addEventListener('change', () => updateTypeVisibility(tpl));
    tpl.querySelector('.action-remove').addEventListener('click', () => {
      tpl.remove();
      renumber();
    });
    tpl.querySelector('.action-test').addEventListener('click', () => testAction(tpl));
    // populate fields from a.config; empty cfg gets type-specific defaults
    let cfg = (a && a.config) || {};
    if (Object.keys(cfg).length === 0 && ACTION_DEFAULTS[type]) {
      cfg = { ...ACTION_DEFAULTS[type] };
    }
    tpl.querySelectorAll('[data-k]').forEach(el => {
      const k = el.dataset.k;
      if (k in cfg) {
        const v = cfg[k];
        if (SECRET_RE.test(k) && typeof v === 'string' && v !== '') {
          el.value = MASK;
        } else if (Array.isArray(v)) {
          el.value = v.join(', ');
        } else if (typeof v === 'object') {
          el.value = JSON.stringify(v);
        } else {
          el.value = v == null ? '' : String(v);
        }
      }
    });
    $('actions-list').append(tpl);
    renumber();
  }

  function renumber() {
    document.querySelectorAll('#actions-list .action .action-index').forEach((el, i) => {
      el.textContent = 'Action ' + (i+1);
    });
  }

  function updateTypeVisibility(node) {
    const t = node.querySelector('.action-type').value;
    node.querySelectorAll('.type-fields').forEach(f => {
      f.style.display = f.classList.contains('type-' + t) ? 'block' : 'none';
    });
  }

  function collectOne(node) {
    const t = node.querySelector('.action-type').value;
    const cfg = {};
    node.querySelectorAll('.type-fields.type-' + t + ' [data-k]').forEach(el => {
      const k = el.dataset.k;
      const v = el.value;
      if (v === '') return;
      if (el.type === 'number' && !isNaN(Number(v))) cfg[k] = Number(v);
      else if (k === 'relays') cfg[k] = v.split(',').map(s=>s.trim()).filter(Boolean);
      else cfg[k] = v;
    });
    return { type: t, config: cfg };
  }

  function collect() {
    const out = {
      subject_npub: subjectNpub,
      silence_threshold: getDur('silence_threshold'),
      warning_interval: getDur('warning_interval'),
      warning_count: parseInt($('warning_count').value || '0', 10),
      check_interval: getDur('check_interval'),
      relays: $('relays').value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean),
      actions: []
    };
    if (initial && initial.watcher_pubkey_hex) out.watcher_pubkey_hex = initial.watcher_pubkey_hex;
    document.querySelectorAll('#actions-list .action').forEach(n => {
      out.actions.push(collectOne(n));
    });
    return out;
  }

  async function testAction(node) {
    const nodes = Array.from(document.querySelectorAll('#actions-list .action'));
    const index = nodes.indexOf(node);
    const msg = node.querySelector('.action-msg');
    const btn = node.querySelector('.action-test');
    const payload = collectOne(node);
    msg.className = 'action-msg msg';
    msg.textContent = '';
    btn.disabled = true;
    const prev = btn.textContent;
    btn.textContent = 'Testing…';
    try {
      const r = await fetch('/admin/config/test-action', {
        method: 'POST',
        headers: {'Content-Type':'application/json','X-CSRF-Token': csrf},
        body: JSON.stringify({type: payload.type, config: payload.config, index: index}),
      });
      if (!r.ok) {
        msg.className = 'action-msg msg err';
        msg.textContent = (await r.text()) || ('HTTP ' + r.status);
        return;
      }
      const data = await r.json();
      if (data.ok) {
        msg.className = 'action-msg msg ok';
        msg.textContent = okMessageFor(payload.type);
      } else {
        msg.className = 'action-msg msg err';
        msg.textContent = data.error || 'action failed';
      }
    } catch (e) {
      msg.className = 'action-msg msg err';
      msg.textContent = String(e);
    } finally {
      btn.disabled = false;
      btn.textContent = prev;
    }
  }

  function okMessageFor(type) {
    switch (type) {
      case 'email': return 'Sent — check the inbox.';
      case 'webhook': return 'Webhook responded OK.';
      case 'nostr_note': return 'Published test note to configured relays.';
      case 'nostr_dm': return 'Encrypted DM published to configured relays.';
      case 'nostr_event': return 'Published pre-signed event.';
      default: return 'Action fired.';
    }
  }

  hydrate(initial || {});

  $('add-action').addEventListener('click', () => { addAction({type:'email', config:{}}); });
  $('relays-defaults').addEventListener('click', () => {
    $('relays').value = (hostRelays || []).join('\n');
  });

  document.querySelectorAll('.dur-toggle').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const wrap = durWrap(btn.dataset.for);
      if (!wrap) return;
      setDurMode(wrap, wrap.dataset.mode === 'raw' ? 'unit' : 'raw');
    });
  });

  $('save').addEventListener('click', async () => {
    let body;
    const rawOverride = $('raw-json').value.trim();
    if (rawOverride) {
      try { body = JSON.parse(rawOverride); }
      catch (e) { showMsg('err', 'invalid raw JSON: ' + e.message); return; }
    } else {
      body = collect();
    }
    try {
      const r = await fetch('/admin/config', {
        method: 'POST',
        headers: {'Content-Type':'application/json','X-CSRF-Token': csrf},
        body: JSON.stringify(body),
        redirect: 'manual'
      });
      if (r.ok || r.type === 'opaqueredirect') { location.reload(); return; }
      showMsg('err', (await r.text()) || ('HTTP ' + r.status));
    } catch (e) {
      showMsg('err', String(e));
    }
  });
</script>
</body>
</html>`))
