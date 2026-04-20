package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func ExecuteActions(ctx context.Context, host *HostConfig, uc *UserConfig,
	watcherPrivHex, watcherPubHex, subjectPubHex string, actions []Action) {
	for _, action := range actions {
		log.Printf("[trigger] executing: %s", action.Type)
		err := executeAction(ctx, action.Type, action.Config, host, uc, watcherPrivHex, watcherPubHex)
		switch {
		case err == errUnknownActionType:
			log.Printf("[trigger] unknown action type: %s", action.Type)
		case err != nil:
			log.Printf("[trigger] %s failed: %v", action.Type, err)
		default:
			log.Printf("[trigger] %s done", action.Type)
		}
	}
}

var errUnknownActionType = fmt.Errorf("unknown action type")

// executeAction dispatches a single action by type. Shared between the
// trigger path (ExecuteActions) and the /admin/config/test-action handler
// so both produce identical side-effects for a given (type, config) pair.
// Does not log the config map — keep secrets out of logs.
func executeAction(ctx context.Context, actionType string, config map[string]any,
	host *HostConfig, uc *UserConfig, watcherPrivHex, watcherPubHex string) error {
	switch actionType {
	case "email":
		return executeEmail(config)
	case "webhook":
		return executeWebhook(ctx, config)
	case "nostr_note":
		return executeNostrNote(ctx, host, uc, watcherPrivHex, watcherPubHex, config)
	case "nostr_dm":
		return executeNostrDM(ctx, host, uc, watcherPrivHex, watcherPubHex, config)
	case "nostr_event":
		return executeNostrEvent(ctx, config)
	default:
		return errUnknownActionType
	}
}

func executeEmail(config map[string]any) error {
	to := getString(config, "to")
	subject := getString(config, "subject")
	body := getString(config, "body")
	smtpHost := getString(config, "smtp_host")
	smtpPort := config["smtp_port"]
	smtpUser := getString(config, "smtp_user")
	smtpPass := getString(config, "smtp_pass")
	from := getString(config, "from")
	if from == "" {
		from = smtpUser
	}

	addr := fmt.Sprintf("%s:%v", smtpHost, smtpPort)
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		from, to, subject, body)

	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
}

func executeWebhook(ctx context.Context, config map[string]any) error {
	url := getString(config, "url")
	method := "POST"
	if m := getString(config, "method"); m != "" {
		method = m
	}

	var bodyReader io.Reader
	if body := getString(config, "body"); body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return err
	}

	if headers, ok := config["headers"].(map[string]any); ok {
		for k, v := range headers {
			req.Header.Set(k, fmt.Sprint(v))
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// resolveRelays picks the effective relay list for an outbound publish.
// Per-action overrides win first, then per-user relays, then host relays.
func resolveRelays(host *HostConfig, uc *UserConfig, actionCfg map[string]any) []string {
	if r, ok := actionCfg["relays"].([]any); ok && len(r) > 0 {
		out := make([]string, len(r))
		for i, v := range r {
			out[i] = fmt.Sprint(v)
		}
		return out
	}
	if uc != nil && len(uc.Relays) > 0 {
		return uc.Relays
	}
	if host != nil {
		return host.Relays
	}
	return nil
}

func executeNostrNote(ctx context.Context, host *HostConfig, uc *UserConfig,
	watcherPrivHex, watcherPubHex string, config map[string]any) error {
	content := getString(config, "content")
	relays := resolveRelays(host, uc, config)

	ev := nostr.Event{
		PubKey:    watcherPubHex,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   content,
		Tags:      nostr.Tags{},
	}
	if err := ev.Sign(watcherPrivHex); err != nil {
		return fmt.Errorf("signing note: %w", err)
	}

	return publishToRelays(ctx, relays, ev)
}

func executeNostrDM(ctx context.Context, host *HostConfig, uc *UserConfig,
	watcherPrivHex, watcherPubHex string, config map[string]any) error {
	toNpub := strings.TrimSpace(getString(config, "to_npub"))
	content := getString(config, "content")
	if toNpub == "" {
		return fmt.Errorf("nostr_dm: to_npub required")
	}
	if content == "" {
		return fmt.Errorf("nostr_dm: content required")
	}
	prefix, data, err := nip19.Decode(toNpub)
	if err != nil || prefix != "npub" {
		return fmt.Errorf("nostr_dm: invalid to_npub")
	}
	recipientHex, ok := data.(string)
	if !ok || recipientHex == "" {
		return fmt.Errorf("nostr_dm: invalid to_npub payload")
	}

	shared, err := nip04.ComputeSharedSecret(recipientHex, watcherPrivHex)
	if err != nil {
		return fmt.Errorf("computing shared secret: %w", err)
	}
	encrypted, err := nip04.Encrypt(content, shared)
	if err != nil {
		return fmt.Errorf("encrypting DM: %w", err)
	}

	ev := nostr.Event{
		PubKey:    watcherPubHex,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      4,
		Content:   encrypted,
		Tags:      nostr.Tags{nostr.Tag{"p", recipientHex}},
	}
	if err := ev.Sign(watcherPrivHex); err != nil {
		return fmt.Errorf("signing DM: %w", err)
	}

	return publishToRelays(ctx, resolveRelays(host, uc, config), ev)
}

func executeNostrEvent(ctx context.Context, config map[string]any) error {
	eventJSON := getString(config, "event_json")

	var ev nostr.Event
	if err := json.Unmarshal([]byte(eventJSON), &ev); err != nil {
		return fmt.Errorf("parsing pre-signed event: %w", err)
	}

	ok, err := ev.CheckSignature()
	if err != nil || !ok {
		return fmt.Errorf("invalid signature on pre-signed event")
	}

	relays := []string{}
	if r, ok := config["relays"].([]any); ok {
		relays = make([]string, len(r))
		for i, v := range r {
			relays[i] = fmt.Sprint(v)
		}
	}
	if len(relays) == 0 {
		return fmt.Errorf("nostr_event action requires relays in config")
	}

	return publishToRelays(ctx, relays, ev)
}

func publishToRelays(ctx context.Context, relays []string, ev nostr.Event) error {
	var lastErr error
	published := 0
	for _, url := range relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			lastErr = err
			continue
		}
		if err := relay.Publish(ctx, ev); err != nil {
			lastErr = err
			relay.Close()
			continue
		}
		relay.Close()
		published++
	}
	if published == 0 && lastErr != nil {
		return fmt.Errorf("failed to publish to any relay: %w", lastErr)
	}
	log.Printf("[nostr] published to %d/%d relays", published, len(relays))
	return nil
}

// SendWarningDM sends an encrypted NIP-04 DM to the subject pubkey.
func SendWarningDM(ctx context.Context, host *HostConfig, uc *UserConfig,
	watcherPrivHex, watcherPubHex, subjectPubHex string, warningNum int) error {
	warningMax := 0
	if uc != nil {
		warningMax = uc.WarningCount
	}
	content := fmt.Sprintf(
		"Dead man's switch warning (%d/%d)\n\n"+
			"No activity detected from your npub for the configured silence period. "+
			"Post anything on Nostr to reset the timer.\n\n"+
			"If no activity is detected after all warnings, the switch will trigger.",
		warningNum, warningMax,
	)

	shared, err := nip04.ComputeSharedSecret(subjectPubHex, watcherPrivHex)
	if err != nil {
		return fmt.Errorf("computing shared secret: %w", err)
	}

	encrypted, err := nip04.Encrypt(content, shared)
	if err != nil {
		return fmt.Errorf("encrypting DM: %w", err)
	}

	ev := nostr.Event{
		PubKey:    watcherPubHex,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      4,
		Content:   encrypted,
		Tags:      nostr.Tags{nostr.Tag{"p", subjectPubHex}},
	}
	if err := ev.Sign(watcherPrivHex); err != nil {
		return fmt.Errorf("signing DM: %w", err)
	}

	relays := resolveRelays(host, uc, nil)
	return publishToRelays(ctx, relays, ev)
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprint(v)
	}
	return ""
}
