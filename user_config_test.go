package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDurationUnmarshalJSONForms(t *testing.T) {
	cases := map[string]time.Duration{
		`"1h"`:      time.Hour,
		`"30m"`:     30 * time.Minute,
		`"1h30m"`:   90 * time.Minute,
		`"2d"`:      48 * time.Hour,
		`"1w"`:      7 * 24 * time.Hour,
		`"1h0m0s"`:  time.Hour,
		`"0s"`:      0,
		`"500ms"`:   500 * time.Millisecond,
	}
	for raw, want := range cases {
		var d Duration
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			t.Fatalf("UnmarshalJSON(%s): %v", raw, err)
		}
		if d.Duration != want {
			t.Fatalf("UnmarshalJSON(%s) = %v, want %v", raw, d.Duration, want)
		}
	}
}

func TestDurationMarshalJSONCanonical(t *testing.T) {
	d := Duration{Duration: time.Hour}
	got, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if string(got) != `"1h0m0s"` {
		t.Fatalf("MarshalJSON: got %s, want \"1h0m0s\"", got)
	}
}

func TestDurationJSONRoundTrip(t *testing.T) {
	inputs := []time.Duration{
		0,
		time.Second,
		time.Minute,
		time.Hour,
		24 * time.Hour,
		7 * 24 * time.Hour,
		90 * time.Minute,
	}
	for _, in := range inputs {
		d := Duration{Duration: in}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", in, err)
		}
		var out Duration
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("Unmarshal(%s): %v", b, err)
		}
		if out.Duration != in {
			t.Fatalf("round-trip %v: got %v", in, out.Duration)
		}
	}
}

func TestDurationYAMLStillAccepted(t *testing.T) {
	// Refactoring the YAML decoder to share parseDurationString must not
	// regress the existing forms.
	cases := map[string]time.Duration{
		"5m": 5 * time.Minute,
		"1h": time.Hour,
		"2d": 48 * time.Hour,
		"1w": 7 * 24 * time.Hour,
	}
	for s, want := range cases {
		var d Duration
		if err := yaml.Unmarshal([]byte(s), &d); err != nil {
			t.Fatalf("yaml.Unmarshal(%q): %v", s, err)
		}
		if d.Duration != want {
			t.Fatalf("yaml %q: got %v want %v", s, d.Duration, want)
		}
	}
}

func sampleUserConfig(t *testing.T) *UserConfig {
	t.Helper()
	return &UserConfig{
		SubjectNpub:      testNpub(t),
		WatcherPubkeyHex: "abcd1234",
		Relays:           []string{"wss://relay.example"},
		SilenceThreshold: Duration{Duration: 14 * 24 * time.Hour},
		WarningInterval:  Duration{Duration: 24 * time.Hour},
		WarningCount:     3,
		CheckInterval:    Duration{Duration: time.Hour},
		Actions: []Action{
			{Type: "webhook", Config: map[string]any{"url": "https://example.com/hook"}},
		},
		UpdatedAt: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
	}
}

func TestUserConfigJSONRoundTrip(t *testing.T) {
	in := sampleUserConfig(t)
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out UserConfig
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, &out) {
		t.Fatalf("round-trip mismatch\nin:  %+v\nout: %+v", in, out)
	}
}

func TestUserConfigJSONSnakeCaseKeys(t *testing.T) {
	in := sampleUserConfig(t)
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	for _, key := range []string{
		`"subject_npub"`,
		`"silence_threshold"`,
		`"warning_interval"`,
		`"warning_count"`,
		`"check_interval"`,
		`"updated_at"`,
		`"type"`,
		`"config"`,
	} {
		if !strings.Contains(s, key) {
			t.Fatalf("missing JSON key %s in %s", key, s)
		}
	}
}

func TestUserConfigValidate(t *testing.T) {
	good := sampleUserConfig(t)
	if err := good.Validate(); err != nil {
		t.Fatalf("Validate on good config: %v", err)
	}

	// Empty Actions is allowed.
	allowEmptyActions := sampleUserConfig(t)
	allowEmptyActions.Actions = nil
	if err := allowEmptyActions.Validate(); err != nil {
		t.Fatalf("Validate with empty Actions: %v", err)
	}

	mutators := map[string]func(*UserConfig){
		"empty subject":          func(c *UserConfig) { c.SubjectNpub = "" },
		"hex subject":            func(c *UserConfig) { c.SubjectNpub = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d" },
		"zero silence":           func(c *UserConfig) { c.SilenceThreshold = Duration{} },
		"negative warning count": func(c *UserConfig) { c.WarningCount = -1 },
		"warning without interval": func(c *UserConfig) {
			c.WarningCount = 2
			c.WarningInterval = Duration{}
		},
		"zero updated_at": func(c *UserConfig) { c.UpdatedAt = time.Time{} },
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			c := sampleUserConfig(t)
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate accepted bad config (%s)", name)
			}
		})
	}
}

func TestUserStoreLoadSaveTypedConfig(t *testing.T) {
	u, _ := NewUserStore(t.TempDir())
	in := sampleUserConfig(t)
	if err := u.CreateUser(in.SubjectNpub); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := u.SaveConfig(in.SubjectNpub, in); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	out, err := u.LoadConfig(in.SubjectNpub)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("LoadConfig mismatch\nin:  %+v\nout: %+v", in, out)
	}
}
