package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	nip19pkg "github.com/nbd-wtf/go-nostr/nip19"
)

const loginVerifyMaxBytes = 16 * 1024

var placeholderRe = regexp.MustCompile(`\[[^\]\n]+\]`)

// displayAddr converts a listen_addr into something clickable in the log.
// ":8080" → "localhost:8080"; "127.0.0.1:8080" → "127.0.0.1:8080".
func displayAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "localhost" + addr
	}
	return addr
}

func (d *DeadManSwitch) startServer(ctx context.Context) {
	if d.cfg.ListenAddr == "" {
		return
	}

	secretPath := filepath.Join(d.cfg.StateDir, "session_secret")
	sm, err := newSessionManager(secretPath)
	if err != nil {
		log.Printf("[server] session init failed: %v", err)
		return
	}
	d.sessions = sm
	if d.challenges == nil {
		d.challenges = newChallengeStore()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleStatus)
	mux.HandleFunc("/health", d.handleHealth)
	mux.HandleFunc("/login", d.handleLogin)
	mux.HandleFunc("/login/challenge", d.handleLoginChallenge)
	mux.HandleFunc("/login/verify", d.handleLoginVerify)
	mux.HandleFunc("/logout", d.handleLogout)
	mux.HandleFunc("/admin", d.requireAuth(d.handleAdmin))
	mux.HandleFunc("/admin/watcher", d.requireAuth(d.handleWatcherSetup))
	mux.HandleFunc("/admin/watcher/generate", d.requireAuth(d.handleWatcherGenerate))
	mux.HandleFunc("/admin/watcher/import", d.requireAuth(d.handleWatcherImport))
	mux.HandleFunc("/admin/watcher/reveal/challenge", d.requireAuth(d.handleWatcherRevealChallenge))
	mux.HandleFunc("/admin/watcher/reveal", d.requireAuth(d.handleWatcherReveal))
	mux.HandleFunc("/admin/config", d.requireAuth(d.handleAdminConfig))
	mux.HandleFunc("/admin/config/test-action", d.requireAuth(d.handleAdminConfigTestAction))

	srv := &http.Server{Addr: d.cfg.ListenAddr, Handler: mux}

	go func() {
		log.Printf("[server] status page at http://%s", displayAddr(d.cfg.ListenAddr))
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("[server] error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()
}

func (d *DeadManSwitch) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.sessions == nil || d.sessions.pubkeyFromRequest(r) == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (d *DeadManSwitch) handleLogin(w http.ResponseWriter, r *http.Request) {
	if d.sessions != nil && d.sessions.pubkeyFromRequest(r) != "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTemplate.Execute(w, nil)
}

func (d *DeadManSwitch) handleLoginChallenge(w http.ResponseWriter, r *http.Request) {
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
	json.NewEncoder(w).Encode(map[string]string{"challenge": c})
}

func (d *DeadManSwitch) handleLoginVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if d.sessions == nil || d.challenges == nil {
		http.Error(w, "auth unavailable", http.StatusServiceUnavailable)
		return
	}
	if !d.cfg.FederationV1 && d.cfg.watchPubkeyHex == "" {
		http.Error(w, "watch_pubkey not configured; dashboard login disabled", http.StatusServiceUnavailable)
		return
	}
	if d.cfg.FederationV1 && d.registry == nil {
		http.Error(w, "registry unavailable", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, loginVerifyMaxBytes))
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

	// Peek the challenge tag so we can look it up in the store.
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

	// In federation mode we accept any signer whose npub is whitelisted
	// and has a running watcher. The signer check runs after we verify
	// the event signature against the signer's own pubkey.
	expectedPub := d.cfg.watchPubkeyHex
	if d.cfg.FederationV1 {
		expectedPub = ""
	}
	pubkey, err := verifyAuthEvent(payload.SignedEvent, challenge, expectedPub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if !d.isAuthorizedLogin(pubkey) {
		http.Error(w, "pubkey not authorized", http.StatusUnauthorized)
		return
	}

	d.sessions.setCookie(w, r, d.sessions.issue(pubkey))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"redirect": "/admin"})
}

// isAuthorizedLogin reports whether the given hex pubkey can establish a
// dashboard session. In federation mode it delegates to the registry: the
// npub must be whitelisted and have a running watcher. In legacy mode it
// matches the single configured watch_pubkey.
func (d *DeadManSwitch) isAuthorizedLogin(pubHex string) bool {
	if pubHex == "" {
		return false
	}
	if d.cfg.FederationV1 {
		if d.registry == nil {
			return false
		}
		npub, err := formatNpub(pubHex)
		if err != nil {
			return false
		}
		return d.registry.IsWhitelisted(npub) && d.registry.IsRunning(npub)
	}
	return pubHex == d.cfg.watchPubkeyHex
}

func (d *DeadManSwitch) handleLogout(w http.ResponseWriter, r *http.Request) {
	if d.sessions != nil {
		d.sessions.clearCookie(w)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (d *DeadManSwitch) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if d.cfg.FederationV1 {
		d.handleAdminFederation(w, r)
		return
	}
	// Legacy mode: no multi-tenancy, so /admin is just a thin signed-in
	// landing page pointing to the read-only status view.
	pubkey := d.sessions.pubkeyFromRequest(r)
	npub, _ := formatNpub(pubkey)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	adminLegacyTemplate.Execute(w, map[string]string{
		"Npub":     truncateMiddle(npub, 24),
		"FullNpub": npub,
	})
}

type healthResponse struct {
	Status         string   `json:"status"`
	LastSeen       string   `json:"last_seen"`
	SilenceSeconds float64  `json:"silence_seconds"`
	WarningsSent   int      `json:"warnings_sent"`
	Triggered      bool     `json:"triggered"`
	ConfigWarnings []string `json:"config_warnings,omitempty"`
}

func (d *DeadManSwitch) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if d.cfg.FederationV1 {
		snaps := []WatcherSnapshot{}
		if d.registry != nil {
			snaps = d.registry.Snapshots()
		}
		out := map[string]any{
			"mode":     "federation",
			"watchers": len(snaps),
		}
		json.NewEncoder(w).Encode(out)
		return
	}

	d.state.mu.Lock()
	resp := healthResponse{
		Status:         d.currentStatus(),
		LastSeen:       d.state.LastSeen.UTC().Format(time.RFC3339),
		SilenceSeconds: time.Since(d.state.LastSeen).Seconds(),
		WarningsSent:   d.state.WarningSent,
		Triggered:      d.state.Triggered,
	}
	d.state.mu.Unlock()

	for _, cw := range d.configWarnings() {
		resp.ConfigWarnings = append(resp.ConfigWarnings, cw.Title)
	}

	json.NewEncoder(w).Encode(resp)
}

type statusData struct {
	LastSeen      string
	SilenceAge    string
	Threshold     string
	WarningsSent  int
	WarningsMax   int
	Triggered     bool
	TriggeredAt   string
	Status        string
	StatusLabel   string
	Progress      int
	TimeRemaining string
	Relays        []RelayStatus
	StartedAt     string
	Warnings      []configWarning
	LoggedIn      bool
}

type configWarning struct {
	Title  string
	Detail string
}

func (d *DeadManSwitch) configWarnings() []configWarning {
	var out []configWarning

	if d.cfg.WatchPubkey == "" {
		out = append(out, configWarning{
			Title:  "Watch pubkey not set",
			Detail: "watch_pubkey is empty. The switch has nothing to monitor and will trigger as soon as silence_threshold elapses.",
		})
	}

	if d.cfg.BotNsec == "" {
		out = append(out, configWarning{
			Title:  "Bot nsec not set",
			Detail: "BOT_NSEC is empty. Warning DMs cannot be signed, so the check-in mechanism will fail silently at the silence threshold. Generate one with `docker compose run --rm deadman --generate-key` and set it in .env.",
		})
	}

	if len(d.cfg.Relays) == 0 {
		out = append(out, configWarning{
			Title:  "No relays configured",
			Detail: "Without relays there is nothing to monitor and nowhere to send warning DMs.",
		})
	}

	if d.cfg.SilenceThreshold.Duration == 0 {
		out = append(out, configWarning{
			Title:  "Silence threshold not set",
			Detail: "silence_threshold is 0 — the switch treats any gap as silent and will trigger immediately at the next check.",
		})
	}

	if len(d.cfg.Actions) == 0 {
		out = append(out, configWarning{
			Title:  "No trigger actions configured",
			Detail: "If the switch triggers, nothing will happen. Add at least one action in config.yaml.",
		})
	}

	out = append(out, actionWarnings(d.cfg.Actions, "config.yaml")...)

	return out
}

// actionWarnings inspects a slice of trigger actions and returns any
// per-action warnings (missing required fields, template placeholders,
// example values). Source is the human-readable origin of the actions
// list — "config.yaml" for legacy, "your config" for federation — and
// appears in detail strings.
func actionWarnings(actions []Action, source string) []configWarning {
	var out []configWarning
	for i, action := range actions {
		label := fmt.Sprintf("Action %d (%s)", i+1, action.Type)
		switch action.Type {
		case "email":
			if to := getString(action.Config, "to"); to != "" {
				label = "Email → " + to
			}
			for _, f := range []string{"smtp_host", "smtp_user", "to", "subject", "body"} {
				if getString(action.Config, f) == "" {
					out = append(out, configWarning{
						Title:  label + ": " + f + " missing",
						Detail: "Required field is empty in " + source + ".",
					})
				}
			}
			if getString(action.Config, "smtp_pass") == "" {
				out = append(out, configWarning{
					Title:  label + ": SMTP password missing",
					Detail: "smtp_pass is empty — the email will fail to authenticate. Set SMTP_PASS in .env.",
				})
			}

			haystack := getString(action.Config, "subject") + "\n" + getString(action.Config, "body")
			if matches := placeholderRe.FindAllString(haystack, -1); len(matches) > 0 {
				seen := map[string]bool{}
				unique := []string{}
				for _, m := range matches {
					if !seen[m] {
						seen[m] = true
						unique = append(unique, m)
					}
				}
				out = append(out, configWarning{
					Title:  label + ": unfilled template placeholders",
					Detail: "Email subject/body contains bracketed placeholders that will be sent literally to the recipient: " + strings.Join(unique, ", ") + ". Fill them in or remove them.",
				})
			}

			for _, f := range []string{"to", "from", "smtp_user"} {
				v := strings.ToLower(getString(action.Config, f))
				if v == "" {
					continue
				}
				if strings.Contains(v, "example.com") || strings.Contains(v, "example.org") ||
					strings.Contains(v, "yourdomain") || strings.HasPrefix(v, "you@") ||
					strings.HasPrefix(v, "spouse@") {
					out = append(out, configWarning{
						Title:  label + ": " + f + " looks like a template value",
						Detail: "Field still contains a template example (" + v + "). Replace with a real address.",
					})
				}
			}
		case "webhook":
			if getString(action.Config, "url") == "" {
				out = append(out, configWarning{
					Title:  label + ": URL missing",
					Detail: "Webhook URL is empty. Check the env var referenced in " + source + " is set in .env.",
				})
			}
		case "nostr_note":
			if getString(action.Config, "content") == "" {
				out = append(out, configWarning{
					Title:  label + ": content missing",
					Detail: "Nostr note action requires a content body in " + source + ".",
				})
			}
		case "nostr_event":
			if getString(action.Config, "event_json") == "" {
				out = append(out, configWarning{
					Title:  label + ": event_json missing",
					Detail: "Pre-signed event JSON is empty in " + source + ".",
				})
			}
		default:
			out = append(out, configWarning{
				Title:  label + ": unknown type",
				Detail: "Action type is not recognised and will be skipped at trigger time.",
			})
		}
	}
	return out
}

func (d *DeadManSwitch) currentStatus() string {
	if d.state.Triggered {
		return "triggered"
	}
	if d.state.WarningSent > 0 {
		return "warning"
	}
	silence := time.Since(d.state.LastSeen)
	if silence > d.cfg.SilenceThreshold.Duration {
		return "warning"
	}
	return "healthy"
}

func (d *DeadManSwitch) handleStatus(w http.ResponseWriter, r *http.Request) {
	if d.cfg.FederationV1 {
		d.handleStatusFederation(w, r)
		return
	}

	loc := d.cfg.location
	tfmt := "2006-01-02 15:04 MST"

	d.state.mu.Lock()
	silence := time.Since(d.state.LastSeen)
	data := statusData{
		LastSeen:     d.state.LastSeen.In(loc).Format(tfmt),
		SilenceAge:   humanDuration(silence),
		Threshold:    humanDuration(d.cfg.SilenceThreshold.Duration),
		WarningsSent: d.state.WarningSent,
		WarningsMax:  d.cfg.WarningCount,
		Triggered:    d.state.Triggered,
		Relays:       d.monitor.Statuses(),
		StartedAt:    d.startedAt.In(loc).Format(tfmt),
	}
	if d.state.TriggeredAt != nil {
		data.TriggeredAt = d.state.TriggeredAt.In(loc).Format(tfmt)
	}
	d.state.mu.Unlock()

	// Compute progress toward trigger
	totalTime := d.cfg.SilenceThreshold.Duration + d.cfg.WarningInterval.Duration*time.Duration(d.cfg.WarningCount)
	data.Progress = int(silence * 100 / totalTime)
	if data.Progress > 100 {
		data.Progress = 100
	}
	if data.Progress < 0 {
		data.Progress = 0
	}

	// Time remaining until trigger
	remaining := totalTime - silence
	if remaining > 0 {
		data.TimeRemaining = humanDuration(remaining)
	} else {
		data.TimeRemaining = "0"
	}

	// Status
	data.Status = d.currentStatus()
	switch data.Status {
	case "healthy":
		data.StatusLabel = "Healthy"
	case "warning":
		data.StatusLabel = "Warning Sent"
	case "triggered":
		data.StatusLabel = "Triggered"
	}

	data.Warnings = d.configWarnings()
	if d.sessions != nil && d.sessions.pubkeyFromRequest(r) != "" {
		data.LoggedIn = true
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	statusTemplate.Execute(w, data)
}

type federationStatusData struct {
	StartedAt string
	Total     int
	Armed     int
	Warning   int
	Triggered int
	LoggedIn  bool
}

const adminConfigMaxBytes = 64 * 1024

// handleAdminConfig dispatches by method. GET renders the field-based
// editor (federation only). POST accepts a JSON UserConfig, merges in
// any secret-placeholder values the form preserved unchanged, and hands
// the result to UserWatcher.PublishConfigDM.
func (d *DeadManSwitch) handleAdminConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		d.handleAdminConfigGet(w, r)
	case http.MethodPost:
		d.handleAdminConfigPost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (d *DeadManSwitch) handleAdminConfigPost(w http.ResponseWriter, r *http.Request) {
	if !d.cfg.FederationV1 {
		http.Error(w, "config editing via web is federation-mode only", http.StatusServiceUnavailable)
		return
	}
	pubkey := d.sessions.pubkeyFromRequest(r)
	// requireAuth already rejects unauthed requests, but belt-and-braces:
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
	if d.registry == nil {
		http.Error(w, "registry unavailable", http.StatusServiceUnavailable)
		return
	}
	watcher := d.registry.Get(npub)
	if watcher == nil {
		http.Error(w, "no watcher running for your npub", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, adminConfigMaxBytes))
	if err != nil {
		http.Error(w, "body too large", http.StatusBadRequest)
		return
	}
	var uc UserConfig
	if err := json.Unmarshal(body, &uc); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	uc.SubjectNpub = npub
	// Preserve secrets the UI rendered as maskedDisplay bullets rather than
	// overwriting them with the placeholder. Matching is by action index +
	// config key, so reordering actions will invalidate the merge — the UI
	// must ask the user to re-enter secrets in that case.
	mergeSecretMasks(&uc, watcher.Config())
	// Validate early so we can return 400 on obvious errors. PublishConfigDM
	// re-validates once it has assigned a monotonic UpdatedAt; this sentinel
	// value is replaced before the real validation.
	uc.UpdatedAt = time.Now()
	if err := uc.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := watcher.PublishConfigDM(r.Context(), &uc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/config", http.StatusSeeOther)
}

func (d *DeadManSwitch) handleStatusFederation(w http.ResponseWriter, r *http.Request) {
	loc := d.cfg.location
	if loc == nil {
		loc = time.UTC
	}
	tfmt := "2006-01-02 15:04 MST"

	data := federationStatusData{
		StartedAt: d.startedAt.In(loc).Format(tfmt),
	}
	if d.registry != nil {
		for _, s := range d.registry.Snapshots() {
			data.Total++
			switch {
			case s.Triggered:
				data.Triggered++
			case s.WarningsSent > 0:
				data.Warning++
			default:
				data.Armed++
			}
		}
	}
	if d.sessions != nil && d.sessions.pubkeyFromRequest(r) != "" {
		data.LoggedIn = true
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	federationStatusTemplate.Execute(w, data)
}

func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh %dm", h, m)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if hours == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd %dh", days, hours)
}

func truncateMiddle(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	half := (maxLen - 3) / 2
	return s[:half] + "..." + s[len(s)-half:]
}

func formatNpub(hexPubkey string) (string, error) {
	return nip19pkg.EncodePublicKey(hexPubkey)
}

var statusTemplate = template.Must(template.New("status").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
` + sharedHead + `
<title>Dead Man's Switch</title>
<style>` + baseCSS + `
  .stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  .stat-label { font-size: var(--text-xs); color: var(--muted); margin-bottom: 0.125rem; }
  .stat-value { font-size: var(--text-base); font-weight: 600; font-variant-numeric: tabular-nums; }
  .stat-value.large { font-size: var(--text-2xl); letter-spacing: -0.01em; }
  .progress-track { height: 6px; background: var(--border); border-radius: 3px; margin-top: 0.75rem; overflow: hidden; }
  .progress-bar { height: 100%; border-radius: 3px; transition: width 1s ease-out; }
  .progress-healthy { background: var(--green); }
  .progress-warning { background: var(--yellow); }
  .progress-triggered { background: var(--red); }
  .meta { font-size: var(--text-xs); color: var(--muted); display: flex; justify-content: space-between; margin-top: 0.5rem; }
  .relay-row { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.375rem; }
  .relay-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
  .relay-url { font-size: var(--text-xs); color: var(--muted); font-family: var(--font-mono); }
</style>
</head>
<body>
<div class="container">
  <h1>
    Dead Man's Switch
    <span class="status-badge status-{{.Status}}">
      <span class="status-dot"></span>
      {{.StatusLabel}}
    </span>
  </h1>

  {{if .Warnings}}
  <div class="warn-banner">
    <div class="warn-banner-header">Configuration Issues ({{len .Warnings}})</div>
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
    <div class="progress-track">
      <div class="progress-bar progress-{{.Status}}" style="width: {{.Progress}}%"></div>
    </div>
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
    <div class="meta"><span>Delete state file to re-arm</span></div>
  </div>
  {{end}}

  <div class="footer">
    Running since {{.StartedAt}}<br>
    <a href="/health">/health</a> · {{if .LoggedIn}}<a href="/admin">admin</a>{{else}}<a href="/login">sign in</a>{{end}}
  </div>
</div>
<script>setTimeout(()=>location.reload(), 60000)</script>
</body>
</html>`))

var loginTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
` + sharedHead + `
<title>Sign in · Dead Man's Switch</title>
<style>` + baseCSS + `
  body { align-items: center; }
  .card { padding: 2rem; max-width: 420px; }
  h1 { margin-bottom: 0.5rem; }
  .subtitle { color: var(--muted); font-size: var(--text-sm); margin-bottom: 1.5rem; line-height: 1.5; }
  button.primary { width: 100%; padding: 0.75rem 1rem; background: var(--accent); color: var(--accent-ink); border: none; border-radius: 0.4rem; font-size: var(--text-sm); font-weight: 600; cursor: pointer; font-family: inherit; }
  button.primary:hover { filter: brightness(1.05); }
  button.primary:disabled { opacity: 0.5; cursor: not-allowed; }
  .hint { color: var(--muted); font-size: var(--text-xs); margin-top: 1rem; text-align: center; line-height: 1.5; }
  .hint a { color: var(--accent); }
  .error { background: rgba(210,104,94,0.08); border: 1px solid rgba(210,104,94,0.4); color: var(--red); padding: 0.75rem; border-radius: 0.4rem; font-size: var(--text-sm); margin-top: 1rem; display: none; }
  .error.show { display: block; }
  .back { display: block; text-align: center; color: var(--muted); font-size: var(--text-xs); margin-top: 1rem; text-decoration: none; }
</style>
</head>
<body>
<div class="card">
  <h1>Sign in</h1>
  <p class="subtitle">Use your Nostr browser extension to sign an authentication challenge. Only whitelisted npubs with an active watcher can sign in.</p>
  <button id="signin" class="primary">Sign in with Nostr</button>
  <div id="err" class="error"></div>
  <p class="hint">Needs a NIP-07 extension such as <a href="https://getalby.com" target="_blank" rel="noopener">Alby</a>, <a href="https://github.com/fiatjaf/nos2x" target="_blank" rel="noopener">nos2x</a>, or nostr-keyx.</p>
  <a href="/" class="back">← back to status</a>
</div>
<script>
const btn = document.getElementById('signin');
const errEl = document.getElementById('err');
function showErr(msg){ errEl.textContent = msg; errEl.classList.add('show'); btn.disabled = false; btn.textContent = 'Sign in with Nostr'; }
btn.addEventListener('click', async () => {
  errEl.classList.remove('show');
  if (typeof window.nostr === 'undefined') { showErr('No Nostr extension detected in this browser.'); return; }
  btn.disabled = true; btn.textContent = 'Signing…';
  try {
    const cr = await fetch('/login/challenge');
    if (!cr.ok) throw new Error('Failed to get challenge');
    const { challenge } = await cr.json();
    const signed = await window.nostr.signEvent({
      kind: 22242,
      created_at: Math.floor(Date.now()/1000),
      tags: [['challenge', challenge]],
      content: 'Sign in to nostr-dead-man-switch'
    });
    const vr = await fetch('/login/verify', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ signedEvent: signed })
    });
    if (!vr.ok) { const t = await vr.text(); throw new Error(t || 'Verification failed'); }
    const { redirect } = await vr.json();
    window.location.href = redirect || '/admin';
  } catch (e) {
    showErr(e.message || String(e));
  }
});
</script>
</body>
</html>`))

var adminLegacyTemplate = template.Must(template.New("adminLegacy").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
` + sharedHead + `
<title>Admin · Dead Man's Switch</title>
<style>` + baseCSS + `
  .label { font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 0.5rem; }
  .value { font-family: var(--font-mono); font-size: var(--text-sm); word-break: break-all; }
  .muted { color: var(--muted); font-size: var(--text-sm); line-height: 1.5; }
</style>
</head>
<body>
<div class="container">
  <h1>Admin</h1>
  <div class="card">
    <div class="label">Signed in as</div>
    <div class="value">{{.Npub}}</div>
  </div>
  <div class="card">
    <div class="muted">This instance is running in legacy single-user mode. The host config is edited in config.yaml on disk; the status page is a read-only view of it.</div>
  </div>
  <div class="actions">
    <a class="btn" href="/">Status</a>
    <form method="POST" action="/logout"><button type="submit" class="btn">Sign out</button></form>
  </div>
</div>
</body>
</html>`))

var federationStatusTemplate = template.Must(template.New("federationStatus").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
` + sharedHead + `
<title>Dead Man's Switch · federation</title>
<style>` + baseCSS + `
  .stat-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 0.75rem; }
  .stat { text-align: center; }
  .stat-label { font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 0.35rem; }
  .stat-value { font-size: var(--text-2xl); font-weight: 600; font-variant-numeric: tabular-nums; letter-spacing: -0.01em; }
  .stat.armed .stat-value { color: var(--green); }
  .stat.warning .stat-value { color: var(--yellow); }
  .stat.triggered .stat-value { color: var(--red); }
  .empty { color: var(--muted); font-style: italic; text-align: center; padding: 0.5rem 0; }
</style>
</head>
<body>
<div class="container">
  <h1>Dead Man's Switch</h1>
  <div class="card">
    <div class="card-title">Watchers</div>
    {{if .Total}}
    <div class="stat-grid">
      <div class="stat"><div class="stat-label">Total</div><div class="stat-value">{{.Total}}</div></div>
      <div class="stat armed"><div class="stat-label">Armed</div><div class="stat-value">{{.Armed}}</div></div>
      <div class="stat warning"><div class="stat-label">Warning</div><div class="stat-value">{{.Warning}}</div></div>
      <div class="stat triggered"><div class="stat-label">Triggered</div><div class="stat-value">{{.Triggered}}</div></div>
    </div>
    {{else}}
    <div class="empty">No watchers running.</div>
    {{end}}
  </div>
  <div class="footer">
    Running since {{.StartedAt}}<br>
    <a href="/health">/health</a> · {{if .LoggedIn}}<a href="/admin">admin</a>{{else}}<a href="/login">sign in</a>{{end}}
  </div>
</div>
</body>
</html>`))
