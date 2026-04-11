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
)

func ExecuteActions(ctx context.Context, cfg *Config, actions []Action) {
	for _, action := range actions {
		log.Printf("[trigger] executing: %s", action.Type)
		var err error
		switch action.Type {
		case "email":
			err = executeEmail(action.Config)
		case "webhook":
			err = executeWebhook(ctx, action.Config)
		case "nostr_note":
			err = executeNostrNote(ctx, cfg, action.Config)
		case "nostr_event":
			err = executeNostrEvent(ctx, action.Config)
		default:
			log.Printf("[trigger] unknown action type: %s", action.Type)
			continue
		}
		if err != nil {
			log.Printf("[trigger] %s failed: %v", action.Type, err)
		} else {
			log.Printf("[trigger] %s done", action.Type)
		}
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

	addr := fmt.Sprintf("%s:%v", smtpHost, smtpPort)
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		smtpUser, to, subject, body)

	return smtp.SendMail(addr, auth, smtpUser, []string{to}, []byte(msg))
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

func executeNostrNote(ctx context.Context, cfg *Config, config map[string]any) error {
	content := getString(config, "content")

	relays := cfg.Relays
	if r, ok := config["relays"].([]any); ok {
		relays = make([]string, len(r))
		for i, v := range r {
			relays[i] = fmt.Sprint(v)
		}
	}

	ev := nostr.Event{
		PubKey:    cfg.botPubkeyHex,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   content,
		Tags:      nostr.Tags{},
	}
	if err := ev.Sign(cfg.botPrivkeyHex); err != nil {
		return fmt.Errorf("signing note: %w", err)
	}

	return publishToRelays(ctx, relays, ev)
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

// SendWarningDM sends an encrypted NIP-04 DM to the watched pubkey.
func SendWarningDM(ctx context.Context, cfg *Config, warningNum int) error {
	content := fmt.Sprintf(
		"Dead man's switch warning (%d/%d)\n\n"+
			"No activity detected from your npub for the configured silence period. "+
			"Post anything on Nostr to reset the timer.\n\n"+
			"If no activity is detected after all warnings, the switch will trigger.",
		warningNum, cfg.WarningCount,
	)

	shared, err := nip04.ComputeSharedSecret(cfg.watchPubkeyHex, cfg.botPrivkeyHex)
	if err != nil {
		return fmt.Errorf("computing shared secret: %w", err)
	}

	encrypted, err := nip04.Encrypt(content, shared)
	if err != nil {
		return fmt.Errorf("encrypting DM: %w", err)
	}

	ev := nostr.Event{
		PubKey:    cfg.botPubkeyHex,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      4,
		Content:   encrypted,
		Tags:      nostr.Tags{nostr.Tag{"p", cfg.watchPubkeyHex}},
	}
	if err := ev.Sign(cfg.botPrivkeyHex); err != nil {
		return fmt.Errorf("signing DM: %w", err)
	}

	return publishToRelays(ctx, cfg.Relays, ev)
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprint(v)
	}
	return ""
}
