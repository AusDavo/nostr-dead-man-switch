package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const maskedDisplay = "••••••••"

var (
	envRefRe    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
	secretKeyRe = regexp.MustCompile(`(?i)pass|passwd|password|token|secret|nsec|privkey|apikey|api_key|watcher_key`)
)

type configField struct {
	Key        string
	Value      string
	Annotation string
	Masked     bool
	IsList     bool
	Items      []string
}

type actionView struct {
	Index  int
	Type   string
	Fields []configField
}

type configViewData struct {
	Npub     string
	FullNpub string
	Core     []configField
	Actions  []actionView
}

func (d *DeadManSwitch) handleConfig(w http.ResponseWriter, r *http.Request) {
	pubkey := d.sessions.pubkeyFromRequest(r)
	npub, _ := formatNpub(pubkey)

	if d.cfg.FederationV1 {
		d.renderFederationConfig(w, r, pubkey, npub)
		return
	}

	data := buildConfigView(d.cfg)
	data.Npub = truncateMiddle(npub, 24)
	data.FullNpub = npub
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	configTemplate.Execute(w, data)
}

type configEditData struct {
	Npub       string
	FullNpub   string
	JSON       string
	CSRF       string
	NotRunning bool
}

func (d *DeadManSwitch) renderFederationConfig(w http.ResponseWriter, r *http.Request, pubkey, npub string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := configEditData{
		Npub:     truncateMiddle(npub, 24),
		FullNpub: npub,
	}
	var watcher *UserWatcher
	if d.registry != nil {
		watcher = d.registry.Get(npub)
	}
	if watcher == nil {
		data.NotRunning = true
		configEditTemplate.Execute(w, data)
		return
	}
	uc := watcher.Config()
	if uc == nil {
		data.NotRunning = true
		configEditTemplate.Execute(w, data)
		return
	}
	pretty, err := json.MarshalIndent(uc, "", "  ")
	if err != nil {
		http.Error(w, "encoding config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	data.JSON = string(pretty)
	data.CSRF = d.sessions.issueCSRFToken(pubkey)
	configEditTemplate.Execute(w, data)
}

func buildConfigView(cfg *Config) configViewData {
	return configViewData{
		Core:    buildCoreFields(cfg),
		Actions: buildActions(cfg),
	}
}

func buildCoreFields(cfg *Config) []configField {
	raw := cfg.RawYAML()
	if raw == nil {
		raw = map[string]any{}
	}
	var out []configField

	out = append(out, maskedField("watch_pubkey", rawString(raw, "watch_pubkey"), cfg.WatchPubkey, "watch_pubkey"))
	out = append(out, maskedField("bot_nsec", rawString(raw, "bot_nsec"), cfg.BotNsec, "bot_nsec"))

	if npub, err := formatNpub(cfg.botPubkeyHex); err == nil && npub != "" {
		out = append(out, configField{Key: "bot_npub (public)", Value: npub})
	}

	out = append(out, configField{Key: "relays", IsList: true, Items: cfg.Relays})
	out = append(out, configField{Key: "silence_threshold", Value: humanDuration(cfg.SilenceThreshold.Duration)})
	out = append(out, configField{Key: "warning_interval", Value: humanDuration(cfg.WarningInterval.Duration)})
	out = append(out, configField{Key: "warning_count", Value: fmt.Sprint(cfg.WarningCount)})
	out = append(out, configField{Key: "check_interval", Value: humanDuration(cfg.CheckInterval.Duration)})
	out = append(out, maskedField("state_file", rawString(raw, "state_file"), cfg.StateFile, "state_file"))
	out = append(out, maskedField("listen_addr", rawString(raw, "listen_addr"), cfg.ListenAddr, "listen_addr"))
	out = append(out, maskedField("timezone", rawString(raw, "timezone"), cfg.Timezone, "timezone"))

	return out
}

func buildActions(cfg *Config) []actionView {
	raw := cfg.RawYAML()
	var rawActions []any
	if raw != nil {
		if a, ok := raw["actions"].([]any); ok {
			rawActions = a
		}
	}

	out := make([]actionView, 0, len(cfg.Actions))
	for i, action := range cfg.Actions {
		var rawCfg map[string]any
		if i < len(rawActions) {
			if m, ok := rawActions[i].(map[string]any); ok {
				if c, ok := m["config"].(map[string]any); ok {
					rawCfg = c
				}
			}
		}
		if rawCfg == nil {
			rawCfg = map[string]any{}
		}

		av := actionView{Index: i + 1, Type: action.Type}
		for _, k := range sortedKeys(action.Config) {
			av.Fields = append(av.Fields, renderField(rawCfg, action.Config, k, "")...)
		}
		out = append(out, av)
	}
	return out
}

func renderField(raw map[string]any, parsed map[string]any, key, prefix string) []configField {
	v := parsed[key]
	rawV := raw[key]
	displayKey := prefix + key

	switch vv := v.(type) {
	case map[string]any:
		rawMap, _ := rawV.(map[string]any)
		if rawMap == nil {
			rawMap = map[string]any{}
		}
		var out []configField
		for _, sub := range sortedKeys(vv) {
			out = append(out, renderField(rawMap, vv, sub, displayKey+".")...)
		}
		return out
	case []any:
		parts := make([]string, len(vv))
		for i, x := range vv {
			parts[i] = fmt.Sprint(x)
		}
		val := strings.Join(parts, ", ")
		rawStr := ""
		if rawList, ok := rawV.([]any); ok {
			rawParts := make([]string, len(rawList))
			for i, x := range rawList {
				rawParts[i] = fmt.Sprint(x)
			}
			rawStr = strings.Join(rawParts, ", ")
		}
		return []configField{maskedField(displayKey, rawStr, val, key)}
	default:
		return []configField{maskedField(displayKey, asString(rawV), fmt.Sprint(v), key)}
	}
}

func maskedField(displayKey, rawStr, val, origKey string) configField {
	f := configField{Key: displayKey, Value: val}

	if rawStr != "" {
		matches := envRefRe.FindAllStringSubmatch(rawStr, -1)
		if len(matches) > 0 {
			names := make([]string, 0, len(matches))
			seen := map[string]bool{}
			for _, m := range matches {
				n := m[1]
				if n == "" {
					n = m[2]
				}
				if !seen[n] {
					seen[n] = true
					names = append(names, "$"+n)
				}
			}
			stripped := envRefRe.ReplaceAllString(rawStr, "")
			if strings.TrimSpace(stripped) == "" {
				f.Annotation = "from " + strings.Join(names, ", ")
			} else {
				f.Annotation = "contains " + strings.Join(names, ", ")
			}
			f.Value = maskedDisplay
			f.Masked = true
			return f
		}
	}

	if isSecretKey(origKey) && val != "" {
		f.Value = maskedDisplay
		f.Masked = true
	}
	return f
}

func isSecretKey(key string) bool {
	if strings.EqualFold(key, "bot_nsec") {
		return true
	}
	return secretKeyRe.MatchString(key)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func rawString(m map[string]any, key string) string {
	return asString(m[key])
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

var configTemplate = template.Must(template.New("config").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Configuration · Dead Man's Switch</title>
<style>
  :root { --bg:#0f1117; --card:#1a1d27; --border:#2a2d3a; --text:#e1e4ed; --muted:#6b7194; --accent:#a78bfa; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; padding:2rem 1rem; display:flex; justify-content:center; }
  .container { max-width:640px; width:100%; }
  h1 { font-size:1.25rem; font-weight:600; margin-bottom:1.5rem; display:flex; justify-content:space-between; align-items:center; gap:0.75rem; }
  .npub { font-family:monospace; font-size:0.8rem; color:var(--muted); font-weight:400; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:0.75rem; padding:1.25rem; margin-bottom:1rem; }
  .card-title { font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:0.75rem; }
  .action-type { color:var(--accent); }
  table { width:100%; border-collapse:collapse; }
  td { padding:0.5rem 0; border-bottom:1px solid var(--border); vertical-align:top; font-size:0.85rem; }
  tr:last-child td { border-bottom:none; }
  td.k { font-family:monospace; color:var(--muted); width:40%; word-break:break-all; padding-right:0.75rem; }
  td.v { font-family:monospace; word-break:break-all; white-space:pre-wrap; }
  .annot { color:var(--accent); font-size:0.75rem; font-family:monospace; margin-left:0.25rem; }
  .masked { color:var(--muted); letter-spacing:0.1em; }
  ul.list { list-style:none; padding:0; margin:0; }
  ul.list li { font-family:monospace; font-size:0.85rem; padding:0.15rem 0; color:var(--text); word-break:break-all; }
  .empty { color:var(--muted); font-style:italic; }
  .actions { display:flex; gap:0.5rem; margin-top:1rem; }
  a.btn { flex:1; padding:0.6rem 0.75rem; border-radius:0.5rem; border:1px solid var(--border); background:transparent; color:var(--text); text-decoration:none; text-align:center; font-size:0.85rem; }
  a.btn:hover { border-color:var(--accent); color:var(--accent); }
  form.btn-form { flex:1; margin:0; }
  form.btn-form button { width:100%; padding:0.6rem 0.75rem; border-radius:0.5rem; border:1px solid var(--border); background:transparent; color:var(--text); text-align:center; font-size:0.85rem; cursor:pointer; font-family:inherit; }
  form.btn-form button:hover { border-color:var(--accent); color:var(--accent); }
</style>
</head>
<body>
<div class="container">
  <h1>
    Configuration
    <span class="npub">{{.Npub}}</span>
  </h1>

  <div class="card">
    <div class="card-title">Core</div>
    <table>
      {{range .Core}}
      <tr>
        <td class="k">{{.Key}}</td>
        <td class="v">
          {{if .IsList}}{{if .Items}}<ul class="list">{{range .Items}}<li>{{.}}</li>{{end}}</ul>{{else}}<span class="empty">(none)</span>{{end}}{{else}}{{if .Masked}}<span class="masked">{{.Value}}</span>{{else}}{{if .Value}}{{.Value}}{{else}}<span class="empty">(empty)</span>{{end}}{{end}}{{if .Annotation}} <span class="annot">({{.Annotation}})</span>{{end}}{{end}}
        </td>
      </tr>
      {{end}}
    </table>
  </div>

  {{range .Actions}}
  <div class="card">
    <div class="card-title">Action {{.Index}} — <span class="action-type">{{.Type}}</span></div>
    {{if .Fields}}
    <table>
      {{range .Fields}}
      <tr>
        <td class="k">{{.Key}}</td>
        <td class="v">{{if .Masked}}<span class="masked">{{.Value}}</span>{{else}}{{if .Value}}{{.Value}}{{else}}<span class="empty">(empty)</span>{{end}}{{end}}{{if .Annotation}} <span class="annot">({{.Annotation}})</span>{{end}}</td>
      </tr>
      {{end}}
    </table>
    {{else}}
    <div class="empty">No config.</div>
    {{end}}
  </div>
  {{end}}

  <div class="actions">
    <a class="btn" href="/">Status</a>
    <a class="btn" href="/admin">Admin</a>
    <form method="POST" action="/logout" class="btn-form"><button type="submit">Sign out</button></form>
  </div>
</div>
</body>
</html>`))

var configEditTemplate = template.Must(template.New("configEdit").Parse(`<!DOCTYPE html>
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
  h1 { font-size:1.25rem; font-weight:600; margin-bottom:1.5rem; display:flex; justify-content:space-between; align-items:center; gap:0.75rem; }
  .npub { font-family:monospace; font-size:0.8rem; color:var(--muted); font-weight:400; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:0.75rem; padding:1.25rem; margin-bottom:1rem; }
  .card-title { font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:0.75rem; }
  textarea { width:100%; min-height:420px; padding:0.75rem; background:var(--bg); border:1px solid var(--border); border-radius:0.5rem; color:var(--text); font-family:monospace; font-size:0.8rem; line-height:1.45; resize:vertical; }
  textarea:focus { outline:none; border-color:var(--accent); }
  button { padding:0.6rem 1rem; border-radius:0.5rem; border:1px solid var(--accent); background:var(--accent); color:#0f1117; font-size:0.9rem; font-weight:600; cursor:pointer; font-family:inherit; }
  button:hover { filter:brightness(1.1); }
  button:disabled { opacity:0.5; cursor:not-allowed; }
  .msg { margin-top:0.75rem; font-size:0.85rem; padding:0.6rem 0.75rem; border-radius:0.5rem; display:none; }
  .msg.err { display:block; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.4); color:var(--red); }
  .msg.ok { display:block; background:rgba(34,197,94,0.1); border:1px solid rgba(34,197,94,0.4); color:var(--green); }
  .muted { color:var(--muted); font-size:0.85rem; line-height:1.5; margin-bottom:0.75rem; }
  .actions { display:flex; gap:0.5rem; margin-top:1rem; }
  a.btn, .actions form button { flex:1; padding:0.6rem 0.75rem; border-radius:0.5rem; border:1px solid var(--border); background:transparent; color:var(--text); text-decoration:none; text-align:center; font-size:0.85rem; cursor:pointer; font-family:inherit; font-weight:400; }
  a.btn:hover, .actions form button:hover { border-color:var(--accent); color:var(--accent); }
  .actions form { flex:1; margin:0; }
  .actions form button { width:100%; }
</style>
</head>
<body>
<div class="container">
  <h1>
    Configuration
    <span class="npub">{{.Npub}}</span>
  </h1>

  {{if .NotRunning}}
  <div class="card">
    <div class="card-title">No watcher running</div>
    <div class="muted">
      Your npub is whitelisted but no UserWatcher is running for it yet. This is the normal state while enrollment completes (the operator may still need to set up your watcher key). Contact the operator if this doesn't resolve on its own.
    </div>
  </div>
  {{else}}
  <div class="card">
    <div class="card-title">UserConfig (JSON)</div>
    <div class="muted">Edit the JSON below and press Save. The change is signed as a self-DM and propagates to peer watchers via the federation fabric; no service restart is required.</div>
    <form id="edit">
      <input type="hidden" id="csrf" value="{{.CSRF}}">
      <textarea id="json" spellcheck="false">{{.JSON}}</textarea>
      <div style="margin-top:0.75rem;display:flex;gap:0.5rem;">
        <button type="submit" id="save">Save</button>
      </div>
      <div id="msg" class="msg"></div>
    </form>
  </div>
  {{end}}

  <div class="actions">
    <a class="btn" href="/">Status</a>
    <a class="btn" href="/admin">Admin</a>
    <form method="POST" action="/logout"><button type="submit">Sign out</button></form>
  </div>
</div>
<script>
const form = document.getElementById('edit');
if (form) {
  const btn = document.getElementById('save');
  const msgEl = document.getElementById('msg');
  function show(cls, m) { msgEl.className = 'msg ' + cls; msgEl.textContent = m; }
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const raw = document.getElementById('json').value;
    let parsed;
    try { parsed = JSON.parse(raw); } catch (err) { show('err', 'invalid JSON: ' + err.message); return; }
    btn.disabled = true; btn.textContent = 'Saving…';
    try {
      const r = await fetch('/admin/config', {
        method: 'POST',
        headers: {'Content-Type':'application/json', 'X-CSRF-Token': document.getElementById('csrf').value},
        body: JSON.stringify(parsed),
        redirect: 'follow'
      });
      if (r.ok) { location.reload(); return; }
      const text = await r.text();
      show('err', text || ('HTTP ' + r.status));
    } catch (err) {
      show('err', String(err));
    } finally {
      btn.disabled = false; btn.textContent = 'Save';
    }
  });
}
</script>
</body>
</html>`))
