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

func (d *DeadManSwitch) startServer(ctx context.Context) {
	if d.cfg.ListenAddr == "" {
		return
	}

	secretPath := filepath.Join(filepath.Dir(d.cfg.StateFile), "session_secret")
	sm, err := newSessionManager(secretPath)
	if err != nil {
		log.Printf("[server] session init failed: %v", err)
		return
	}
	d.sessions = sm

	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleStatus)
	mux.HandleFunc("/health", d.handleHealth)
	mux.HandleFunc("/login", d.handleLogin)
	mux.HandleFunc("/login/challenge", d.handleLoginChallenge)
	mux.HandleFunc("/login/verify", d.handleLoginVerify)
	mux.HandleFunc("/logout", d.handleLogout)
	mux.HandleFunc("/admin", d.requireAuth(d.handleAdmin))

	srv := &http.Server{Addr: d.cfg.ListenAddr, Handler: mux}

	go func() {
		log.Printf("[server] status page at http://localhost%s", d.cfg.ListenAddr)
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
	if d.cfg.watchPubkeyHex == "" {
		http.Error(w, "watch_pubkey not configured; dashboard login disabled", http.StatusServiceUnavailable)
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

	pubkey, err := verifyAuthEvent(payload.SignedEvent, challenge, d.cfg.watchPubkeyHex)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	d.sessions.setCookie(w, r, d.sessions.issue(pubkey))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"redirect": "/admin"})
}

func (d *DeadManSwitch) handleLogout(w http.ResponseWriter, r *http.Request) {
	if d.sessions != nil {
		d.sessions.clearCookie(w)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (d *DeadManSwitch) handleAdmin(w http.ResponseWriter, r *http.Request) {
	pubkey := d.sessions.pubkeyFromRequest(r)
	npub, _ := formatNpub(pubkey)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	adminTemplate.Execute(w, map[string]string{
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type statusData struct {
	WatchPubkey   string
	BotNpub       string
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

	for i, action := range d.cfg.Actions {
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
						Detail: "Required field is empty in config.yaml.",
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
					Detail: "Webhook URL is empty. Check the env var referenced in config.yaml is set in .env.",
				})
			}
		case "nostr_note":
			if getString(action.Config, "content") == "" {
				out = append(out, configWarning{
					Title:  label + ": content missing",
					Detail: "Nostr note action requires a content body in config.yaml.",
				})
			}
		case "nostr_event":
			if getString(action.Config, "event_json") == "" {
				out = append(out, configWarning{
					Title:  label + ": event_json missing",
					Detail: "Pre-signed event JSON is empty in config.yaml.",
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
	loc := d.cfg.location
	tfmt := "2006-01-02 15:04 MST"

	d.state.mu.Lock()
	silence := time.Since(d.state.LastSeen)
	data := statusData{
		WatchPubkey:  truncateMiddle(d.cfg.WatchPubkey, 20),
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

	// Bot npub for display
	if npub, err := formatNpub(d.cfg.botPubkeyHex); err == nil {
		data.BotNpub = truncateMiddle(npub, 20)
	}

	data.Warnings = d.configWarnings()
	if d.sessions != nil && d.sessions.pubkeyFromRequest(r) != "" {
		data.LoggedIn = true
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	statusTemplate.Execute(w, data)
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
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dead Man's Switch</title>
<style>
  :root {
    --bg: #0f1117;
    --card: #1a1d27;
    --border: #2a2d3a;
    --text: #e1e4ed;
    --muted: #6b7194;
    --green: #22c55e;
    --yellow: #eab308;
    --red: #ef4444;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    justify-content: center;
    padding: 2rem 1rem;
  }
  .container { max-width: 480px; width: 100%; }
  h1 {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.8rem;
    font-weight: 500;
  }
  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }
  .status-healthy .status-dot { background: var(--green); box-shadow: 0 0 8px var(--green); }
  .status-healthy { background: rgba(34,197,94,0.1); color: var(--green); }
  .status-warning .status-dot { background: var(--yellow); box-shadow: 0 0 8px var(--yellow); }
  .status-warning { background: rgba(234,179,8,0.1); color: var(--yellow); }
  .status-triggered .status-dot { background: var(--red); box-shadow: 0 0 8px var(--red); }
  .status-triggered { background: rgba(239,68,68,0.1); color: var(--red); }

  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    padding: 1.25rem;
    margin-bottom: 1rem;
  }
  .card-title {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-bottom: 0.75rem;
  }
  .stat-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }
  .stat-label {
    font-size: 0.75rem;
    color: var(--muted);
    margin-bottom: 0.125rem;
  }
  .stat-value {
    font-size: 1.1rem;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .stat-value.large {
    font-size: 1.5rem;
  }

  .progress-track {
    height: 6px;
    background: var(--border);
    border-radius: 3px;
    margin-top: 0.75rem;
    overflow: hidden;
  }
  .progress-bar {
    height: 100%;
    border-radius: 3px;
    transition: width 1s ease;
  }
  .progress-healthy { background: var(--green); }
  .progress-warning { background: var(--yellow); }
  .progress-triggered { background: var(--red); }

  .meta {
    font-size: 0.75rem;
    color: var(--muted);
    display: flex;
    justify-content: space-between;
    margin-top: 0.5rem;
  }
  .footer {
    text-align: center;
    font-size: 0.7rem;
    color: var(--muted);
    margin-top: 1rem;
  }
  .footer a { color: var(--muted); }
  .relay-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.375rem;
  }
  .warn-card {
    background: rgba(234,179,8,0.08);
    border-color: rgba(234,179,8,0.4);
  }
  .warn-card .card-title { color: var(--yellow); }
  .warn-row {
    padding: 0.5rem 0;
    border-bottom: 1px solid rgba(234,179,8,0.15);
  }
  .warn-row:last-child { border-bottom: none; }
  .warn-title {
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--yellow);
    margin-bottom: 0.2rem;
  }
  .warn-detail {
    font-size: 0.75rem;
    color: var(--muted);
    line-height: 1.4;
  }
  .relay-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .relay-url {
    font-size: 0.8rem;
    color: var(--muted);
    font-family: monospace;
  }
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

  <div class="card">
    <div class="card-title">Identity</div>
    <div class="stat-grid">
      <div>
        <div class="stat-label">Watching</div>
        <div class="stat-value" style="font-size:0.85rem">{{.WatchPubkey}}</div>
      </div>
      <div>
        <div class="stat-label">Bot</div>
        <div class="stat-value" style="font-size:0.85rem">{{.BotNpub}}</div>
      </div>
    </div>
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
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · Dead Man's Switch</title>
<style>
  :root { --bg:#0f1117; --card:#1a1d27; --border:#2a2d3a; --text:#e1e4ed; --muted:#6b7194; --accent:#a78bfa; --red:#ef4444; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; display:flex; align-items:center; justify-content:center; padding:2rem 1rem; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:0.75rem; padding:2rem; max-width:420px; width:100%; }
  h1 { font-size:1.25rem; font-weight:600; margin-bottom:0.5rem; }
  .subtitle { color:var(--muted); font-size:0.9rem; margin-bottom:1.5rem; line-height:1.5; }
  button { width:100%; padding:0.75rem 1rem; background:var(--accent); color:#0f1117; border:none; border-radius:0.5rem; font-size:0.95rem; font-weight:600; cursor:pointer; }
  button:hover { filter:brightness(1.1); }
  button:disabled { opacity:0.5; cursor:not-allowed; }
  .hint { color:var(--muted); font-size:0.8rem; margin-top:1rem; text-align:center; line-height:1.5; }
  .hint a { color:var(--accent); }
  .error { background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.4); color:var(--red); padding:0.75rem; border-radius:0.5rem; font-size:0.85rem; margin-top:1rem; display:none; }
  .error.show { display:block; }
  .back { display:block; text-align:center; color:var(--muted); font-size:0.8rem; margin-top:1rem; text-decoration:none; }
</style>
</head>
<body>
<div class="card">
  <h1>Sign in</h1>
  <p class="subtitle">Use your Nostr browser extension to sign an authentication challenge. Only the pubkey set as <code>watch_pubkey</code> can sign in.</p>
  <button id="signin">Sign in with Nostr</button>
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

var adminTemplate = template.Must(template.New("admin").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin · Dead Man's Switch</title>
<style>
  :root { --bg:#0f1117; --card:#1a1d27; --border:#2a2d3a; --text:#e1e4ed; --muted:#6b7194; --accent:#a78bfa; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; padding:2rem 1rem; display:flex; justify-content:center; }
  .container { max-width:480px; width:100%; }
  h1 { font-size:1.25rem; font-weight:600; margin-bottom:1.5rem; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:0.75rem; padding:1.25rem; margin-bottom:1rem; }
  .label { font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:0.5rem; }
  .value { font-family:monospace; font-size:0.9rem; word-break:break-all; }
  .muted { color:var(--muted); font-size:0.85rem; line-height:1.5; }
  .actions { display:flex; gap:0.5rem; margin-top:1rem; }
  a.btn, button.btn { flex:1; padding:0.6rem 0.75rem; border-radius:0.5rem; border:1px solid var(--border); background:transparent; color:var(--text); text-decoration:none; text-align:center; font-size:0.85rem; cursor:pointer; font-family:inherit; }
  a.btn:hover, button.btn:hover { border-color:var(--accent); color:var(--accent); }
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
    <div class="muted">Configuration editing is not wired up yet — this placeholder confirms the auth flow works end-to-end. Edit forms ship in a later PR.</div>
  </div>
  <div class="actions">
    <a class="btn" href="/">Status</a>
    <form method="POST" action="/logout" style="flex:1;margin:0"><button type="submit" class="btn" style="width:100%">Sign out</button></form>
  </div>
</div>
</body>
</html>`))
