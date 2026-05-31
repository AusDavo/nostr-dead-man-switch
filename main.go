package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	genKey := flag.Bool("generate-key", false, "generate a new bot keypair and exit")
	resetSession := flag.Bool("reset-session", false, "rotate the dashboard session secret (invalidates all logins) and exit")
	whitelistAdd := flag.String("whitelist-add", "", "add npub to whitelist and exit")
	whitelistNote := flag.String("whitelist-note", "", "note to attach with --whitelist-add")
	whitelistRemove := flag.String("whitelist-remove", "", "remove npub from whitelist and exit")
	whitelistList := flag.Bool("whitelist-list", false, "list whitelist entries and exit")
	grantFree := flag.String("grant-free", "", "add npub to whitelist as plan=free and exit")
	generateInvite := flag.Bool("generate-invite", false, "mint a new invite code and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	if *genKey {
		generateKey()
		return
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *resetSession {
		path := filepath.Join(cfg.StateDir, "session_secret")
		if err := rotateSessionSecret(path); err != nil {
			log.Fatalf("Failed to rotate session secret: %v", err)
		}
		fmt.Printf("Session secret rotated. All existing dashboard sessions are invalidated.\nSecret file: %s\n", path)
		return
	}

	if handled, err := handleWhitelistCLI(os.Stdout, cfg.WhitelistFile, *whitelistAdd, *whitelistNote, *whitelistRemove, *whitelistList); err != nil {
		log.Fatalf("Whitelist: %v", err)
	} else if handled {
		return
	}

	if *grantFree != "" {
		wl, err := LoadWhitelist(cfg.WhitelistFile)
		if err != nil {
			log.Fatalf("Whitelist: %v", err)
		}
		if err := wl.Add(*grantFree, "granted by admin (cli)"); err != nil {
			log.Fatalf("grant-free: %v", err)
		}
		if err := wl.SetPlanKind(*grantFree, "free"); err != nil {
			log.Fatalf("grant-free: %v", err)
		}
		fmt.Printf("granted %s as plan=free (%s)\n", *grantFree, cfg.WhitelistFile)
		return
	}

	if *generateInvite {
		invites, err := LoadInviteCodes(cfg.StateDir, cfg.InviteCodes)
		if err != nil {
			log.Fatalf("generate-invite: %v", err)
		}
		code, err := invites.Mint()
		if err != nil {
			log.Fatalf("generate-invite: %v", err)
		}
		fmt.Printf("new invite code: %s\nshare: /admin/signup?code=%s\n", code, code)
		return
	}

	log.Printf("nostr-deadman %s starting", version)

	state, err := LoadState(cfg.StateFile)
	if err != nil {
		log.Printf("No existing state, starting fresh")
		state = NewState()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	dms := NewDeadManSwitch(cfg, state)
	if err := dms.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("Fatal error: %v", err)
	}
}

func generateKey() {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	nsec, _ := nip19.EncodePrivateKey(sk)
	npub, _ := nip19.EncodePublicKey(pk)
	fmt.Printf("Private key (nsec): %s\n", nsec)
	fmt.Printf("Public key (npub):  %s\n\n", npub)
	fmt.Println("Add the nsec to your config.yaml as bot_nsec.")
	fmt.Println("Share the npub so contacts know your bot's identity.")
}
