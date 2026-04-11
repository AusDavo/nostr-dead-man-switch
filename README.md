# nostr-dead-man-switch

A Nostr-native dead man's switch. Instead of manual check-ins, it passively monitors your npub across relays. Posts, reactions, zaps — any signed event resets the timer. Your normal Nostr usage is your proof of life.

If you go silent for X days, it sends you a private DM as a last-resort check-in. No response? It tries once more. Still nothing? It triggers — sends emails, publishes notes, hits webhooks, whatever you've configured.

## Why this over existing tools

Existing dead man's switches ([Aeterna](https://github.com/alpyxn/aeterna), [LastSignal](https://github.com/giovantenne/lastsignal)) require you to remember to check in on a schedule. That works until it doesn't — and the failure mode is *triggering when you're alive but forgot*.

This monitors your actual activity:

- **No check-in fatigue** — you don't have to remember to click a link or enter a code every month forever
- **Cryptographic proof** — events are signed with your key, not just "someone clicked an email link"
- **Stays inside Nostr** — monitoring and check-in DMs all happen on the protocol, only the final payload actions go outside
- **Dead simple to run** — it's a relay subscription, a timestamp, and a timer

## How it works

```
Monitor npub across relays
         │
    Any event? ──yes──→ Reset timer
         │
         no (silence threshold exceeded)
         │
    Send warning DM #1
         │
    Wait... any event? ──yes──→ Reset timer
         │
         no
         │
    Send warning DM #2
         │
    Wait... any event? ──yes──→ Reset timer
         │
         no
         │
    ┌─────────────┐
    │   TRIGGER    │
    │              │
    │  • emails    │
    │  • webhooks  │
    │  • notes     │
    └─────────────┘
```

## Quick start

### Docker (recommended)

```bash
# Clone
git clone https://github.com/AusDavo/nostr-dead-man-switch.git
cd nostr-dead-man-switch

# Generate a bot keypair
docker compose run --rm deadman --generate-key

# Set up secrets
cp .env.example .env
# Edit .env with the bot nsec you just generated (and SMTP password if using email)

# Set up config
cp config.example.yaml config.yaml
# Edit config.yaml with your npub, relays, timing, and actions

# Run
docker compose up -d

# Status page at http://localhost:8080
```

### Build from source

```bash
go build -o nostr-deadman .
./nostr-deadman -config config.yaml
```

## Configuration

See [config.example.yaml](config.example.yaml) for the full reference. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `watch_pubkey` | — | npub or hex pubkey to monitor |
| `bot_nsec` | — | Bot's private key for sending warning DMs |
| `relays` | — | Relay WebSocket URLs to monitor |
| `silence_threshold` | — | How long of silence before first warning (e.g. `30d`, `4w`, `720h`) |
| `warning_interval` | `24h` | Time between warning DMs |
| `warning_count` | `2` | Number of warning DMs before triggering |
| `check_interval` | `1h` | How often to evaluate the timer |
| `listen_addr` | — | Status page address (e.g. `:8080`). Empty = disabled |
| `state_file` | `state.json` | Where to persist state |

Secrets go in `.env` (see [.env.example](.env.example)) and are expanded in the config via `${VAR_NAME}`.

## Trigger actions

### Email

```yaml
- type: email
  config:
    to: "loved-one@example.com"
    subject: "Automated message"
    body: "This is an automated message from my dead man's switch."
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_user: "you@gmail.com"
    smtp_pass: "${SMTP_PASSWORD}"
```

### Webhook

```yaml
- type: webhook
  config:
    url: "https://example.com/hook"
    method: "POST"
    headers:
      Content-Type: "application/json"
      Authorization: "Bearer ${TOKEN}"
    body: '{"triggered": true}'
```

### Nostr note (signed by bot)

```yaml
- type: nostr_note
  config:
    content: "This is an automated message from my dead man's switch."
    relays:
      - "wss://relay.damus.io"
```

### Pre-signed Nostr event

Sign an event with your own key ahead of time — the bot just publishes it. Never needs your nsec.

```yaml
- type: nostr_event
  config:
    event_json: '{"id":"...","pubkey":"...","sig":"...","kind":1,"content":"...","tags":[],"created_at":0}'
    relays:
      - "wss://relay.damus.io"
      - "wss://nos.lol"
```

## Status page

Set `listen_addr: ":8080"` in your config to enable a status dashboard. Shows current silence duration, timer progress, warning state, and connected relays. Auto-refreshes every 60 seconds.

A `/health` JSON endpoint is also available for monitoring:

```json
{"status":"healthy","last_seen":"2026-04-11T12:00:00Z","silence_seconds":3600,"warnings_sent":0,"triggered":false}
```

## State and re-arming

State is persisted to a JSON file (default: `state.json`). To re-arm the switch after it triggers, delete the state file and restart.

The state file tracks:
- Last seen event timestamp
- Number of warnings sent
- Whether the switch has triggered

## Generate a bot key

```bash
docker compose run --rm deadman --generate-key
```

Use a dedicated keypair for the bot. Do **not** use your main nsec.

## License

MIT
