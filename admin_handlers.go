package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

type watcherSetupData struct {
	Npub         string
	FullNpub     string
	CSRF         string
	AlreadySetup bool
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
  .warn-banner { background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.35); color:var(--red); padding:0.75rem 1rem; border-radius:0.5rem; font-size:0.85rem; margin-bottom:1.25rem; line-height:1.5; }
  .actions { display:flex; gap:0.5rem; margin-top:1rem; }
  a.btn { flex:1; padding:0.6rem 0.75rem; border-radius:0.5rem; border:1px solid var(--border); background:transparent; color:var(--text); text-decoration:none; text-align:center; font-size:0.85rem; }
  a.btn:hover { border-color:var(--accent); color:var(--accent); }
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
    <div class="card-title">Watcher already set up</div>
    <div class="muted">
      A sealed bot key is already on file for your npub. Use the admin dashboard to check status or edit your config.
    </div>
    <div class="actions">
      <a class="btn" href="/admin">Go to admin</a>
      <a class="btn" href="/admin/config">Configuration</a>
    </div>
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
