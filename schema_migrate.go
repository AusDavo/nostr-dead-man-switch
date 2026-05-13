package main

import (
	"encoding/json"
	"fmt"
)

const (
	stateSchemaCurrent   = 1
	userCfgSchemaCurrent = 1
)

// peekSchemaVersion decodes only the schema_version field. Returns 0
// (the zero value) when the field is absent, which is the convention
// for legacy/unversioned files.
func peekSchemaVersion(data []byte) (int, error) {
	var peek struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return 0, fmt.Errorf("peeking schema_version: %w", err)
	}
	return peek.SchemaVersion, nil
}

// migrateState transforms raw state.json bytes from any supported
// version up to stateSchemaCurrent. Returns the (possibly-rewritten)
// bytes, a bool indicating whether a migration was actually applied
// (caller decides whether to eagerly rewrite the file on disk), and
// any error. Refuses bytes claiming a version newer than this binary
// knows.
func migrateState(data []byte) ([]byte, bool, error) {
	v, err := peekSchemaVersion(data)
	if err != nil {
		return nil, false, err
	}
	if v > stateSchemaCurrent {
		return nil, false, fmt.Errorf("state schema v%d is newer than this binary supports (v%d) — upgrade required", v, stateSchemaCurrent)
	}
	if v == stateSchemaCurrent {
		return data, false, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false, fmt.Errorf("decoding state for v0→v1: %w", err)
	}
	m["schema_version"] = json.RawMessage(fmt.Sprintf("%d", stateSchemaCurrent))
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, false, fmt.Errorf("encoding migrated state: %w", err)
	}
	return out, true, nil
}

// migrateUserConfig is the analogue of migrateState for config.json.
func migrateUserConfig(data []byte) ([]byte, bool, error) {
	v, err := peekSchemaVersion(data)
	if err != nil {
		return nil, false, err
	}
	if v > userCfgSchemaCurrent {
		return nil, false, fmt.Errorf("user_config schema v%d is newer than this binary supports (v%d) — upgrade required", v, userCfgSchemaCurrent)
	}
	if v == userCfgSchemaCurrent {
		return data, false, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false, fmt.Errorf("decoding user_config for v0→v1: %w", err)
	}
	m["schema_version"] = json.RawMessage(fmt.Sprintf("%d", userCfgSchemaCurrent))
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, false, fmt.Errorf("encoding migrated user_config: %w", err)
	}
	return out, true, nil
}
