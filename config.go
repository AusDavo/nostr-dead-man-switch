package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"gopkg.in/yaml.v3"
)

type Config struct {
	WatchPubkey      string   `yaml:"watch_pubkey"`
	BotNsec          string   `yaml:"bot_nsec"`
	Relays           []string `yaml:"relays"`
	SilenceThreshold Duration `yaml:"silence_threshold"`
	WarningInterval  Duration `yaml:"warning_interval"`
	WarningCount     int      `yaml:"warning_count"`
	CheckInterval    Duration `yaml:"check_interval"`
	StateFile        string   `yaml:"state_file"`
	ListenAddr       string   `yaml:"listen_addr"`
	Timezone         string   `yaml:"timezone"`
	Actions          []Action `yaml:"actions"`

	// Derived at load time
	watchPubkeyHex string
	botPrivkeyHex  string
	botPubkeyHex   string
	location       *time.Location

	// rawYAML holds the parsed YAML before os.ExpandEnv, so callers can
	// detect ${VAR} references for secret masking on the /config view.
	rawYAML map[string]any
}

// RawYAML returns the parsed config before environment-variable expansion.
// Values containing "${VAR}" reveal where a secret was sourced from.
func (c *Config) RawYAML() map[string]any {
	return c.rawYAML
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	re := regexp.MustCompile(`^(\d+)([dwh])$`)
	if matches := re.FindStringSubmatch(s); matches != nil {
		n, _ := strconv.Atoi(matches[1])
		switch matches[2] {
		case "d":
			d.Duration = time.Duration(n) * 24 * time.Hour
			return nil
		case "w":
			d.Duration = time.Duration(n) * 7 * 24 * time.Hour
			return nil
		}
	}
	var err error
	d.Duration, err = time.ParseDuration(s)
	return err
}

type Action struct {
	Type   string         `yaml:"type"`
	Config map[string]any `yaml:"config"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing raw config: %w", err)
	}

	data = []byte(os.ExpandEnv(string(data)))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg.rawYAML = raw

	// Decode watch pubkey (npub or hex)
	if strings.HasPrefix(cfg.WatchPubkey, "npub") {
		_, v, err := nip19.Decode(cfg.WatchPubkey)
		if err != nil {
			return nil, fmt.Errorf("decoding npub: %w", err)
		}
		cfg.watchPubkeyHex = v.(string)
	} else {
		cfg.watchPubkeyHex = cfg.WatchPubkey
	}

	// Decode bot nsec
	if strings.HasPrefix(cfg.BotNsec, "nsec") {
		_, v, err := nip19.Decode(cfg.BotNsec)
		if err != nil {
			return nil, fmt.Errorf("decoding nsec: %w", err)
		}
		cfg.botPrivkeyHex = v.(string)
	} else {
		cfg.botPrivkeyHex = cfg.BotNsec
	}

	pub, err := nostr.GetPublicKey(cfg.botPrivkeyHex)
	if err != nil {
		return nil, fmt.Errorf("deriving bot pubkey: %w", err)
	}
	cfg.botPubkeyHex = pub

	// Defaults
	if cfg.WarningCount == 0 {
		cfg.WarningCount = 2
	}
	if cfg.CheckInterval.Duration == 0 {
		cfg.CheckInterval.Duration = 1 * time.Hour
	}
	if cfg.StateFile == "" {
		cfg.StateFile = "state.json"
	}
	if cfg.WarningInterval.Duration == 0 {
		cfg.WarningInterval.Duration = 24 * time.Hour
	}

	if cfg.Timezone != "" {
		loc, err := time.LoadLocation(cfg.Timezone)
		if err != nil {
			return nil, fmt.Errorf("invalid timezone %q: %w", cfg.Timezone, err)
		}
		cfg.location = loc
	} else {
		cfg.location = time.UTC
	}

	return &cfg, nil
}
