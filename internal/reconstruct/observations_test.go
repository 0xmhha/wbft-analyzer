package reconstruct

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func syntheticObservedInputs(t *testing.T, m Manifest, change func([]map[string]any)) File {
	t.Helper()
	sum := sha256.Sum256([]byte{1, 2})
	frameRun := "synthetic-process"
	rows := []map[string]any{
		{"type": "capture_start", "format": "wbft-input-observations/1", "node": m.Node, "run": "synthetic-inputs", "frame_run": frameRun, "genesis_sha256": m.Genesis.SHA256, "binary_sha256": strings.Repeat("3", 64), "source_commit": strings.Repeat("4", 40)},
		{"type": "begin", "ordinal": "1", "instance": "1", "kind": "start"},
		{"type": "answer", "ordinal": "1", "instance": "1", "method": "head", "outcome": "available", "head_proposer": m.Node, "payload_available": true, "payload": "0x0102", "payload_sha256": hex.EncodeToString(sum[:])},
		{"type": "end", "ordinal": "1", "instance": "1", "height": "1", "round": "0", "state": "Accept request", "proposer": m.Node, "valset_digest": "0x" + strings.Repeat("5", 64), "config": map[string]string{"request_timeout_ms": "2000", "block_period_seconds": "1", "epoch": "10", "max_request_timeout_seconds": "0", "allowed_future_block_seconds": "0", "proposer_policy": "0"}},
		{"type": "capture_end", "dropped": "0"},
	}
	for i, row := range rows {
		row["sequence"], row["t_wall"], row["t_mono_ns"] = strconv.Itoa(i+1), processingWall(i), strconv.Itoa(i)
	}
	if change != nil {
		change(rows)
	}
	var raw bytes.Buffer
	for _, row := range rows {
		if err := json.NewEncoder(&raw).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	return sourceFile(t, t.TempDir(), "local-inputs.jsonl", raw.Bytes())
}

func TestInputObservationPresenceDoesNotPromoteInfoLogReadiness(t *testing.T) {
	m := sourceManifest(t, "1", false)
	genesis := sourceFile(t, t.TempDir(), "local-genesis.json", []byte(syntheticGenesisConfig))
	m.Genesis = &genesis
	inputs := syntheticObservedInputs(t, m, nil)
	m.Inputs = &inputs
	a, err := Assess(t.Context(), m, "1", "1")
	if err != nil || a.CoreExecuted || a.Heights[0].Status != "not_possible" || a.Sources.Inputs == nil {
		t.Fatal(a, err)
	}
	s := a.Sources.Inputs
	if s.SHA256 != inputs.SHA256 || s.GenesisSHA != genesis.SHA256 || !s.CaptureComplete || s.Inputs != 1 || s.Answers != 1 || s.DeclaredScopeMatches != 0 {
		t.Fatal(s)
	}
	encoded, _ := json.Marshal(a)
	for _, private := range []string{inputs.Path, genesis.Path, "0x0102", "NEVER_PROJECTED", "PRIVATE_PAYLOAD"} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("local source or raw application value escaped", private)
		}
	}
	file, err := LoadManifest(t.Context(), sourceFile(t, filepath.Dir(inputs.Path), "manifest.json", mustObservationManifestJSON(t, m)).Path)
	if err != nil || file.Inputs.Path != inputs.Path {
		t.Fatal(file, err)
	}
}

func mustObservationManifestJSON(t *testing.T, m Manifest) []byte {
	t.Helper()
	copyInput := *m.Inputs
	copyInput.Path = filepath.Base(copyInput.Path)
	m.Inputs = &copyInput
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestInputObservationForeignIdentityAndChecksumRefusedAsWhole(t *testing.T) {
	for _, change := range []func([]map[string]any){
		func(r []map[string]any) { r[0]["node"] = "0x" + strings.Repeat("7", 40) },
		func(r []map[string]any) { r[0]["genesis_sha256"] = strings.Repeat("8", 64) },
		func(r []map[string]any) { r[2]["payload"] = "0x0304" },
	} {
		m := sourceManifest(t, "1", true)
		genesis := sourceFile(t, t.TempDir(), "local-genesis.json", []byte(syntheticGenesisConfig))
		m.Genesis = &genesis
		inputs := syntheticObservedInputs(t, m, change)
		m.Inputs = &inputs
		a, err := Assess(t.Context(), m, "1", "1")
		if err == nil || a.Node != "" || len(a.Heights) != 0 {
			t.Fatal("foreign source exposed partial assessment", a, err)
		}
	}
	m := sourceManifest(t, "1", true)
	genesis := sourceFile(t, t.TempDir(), "local-genesis.json", []byte(syntheticGenesisConfig))
	m.Genesis = &genesis
	inputs := syntheticObservedInputs(t, m, nil)
	m.Inputs = &inputs
	m.Inputs.SHA256 = strings.Repeat("9", 64)
	if _, err := Assess(t.Context(), m, "1", "1"); err == nil {
		t.Fatal("checksum substitution accepted")
	}
	m.Genesis = nil
	if validManifest(m) {
		t.Fatal("observed genesis has no supplied configuration")
	}
}

func TestDeclaredInputExecutionMatchesOnlyItsInstanceAndInterval(t *testing.T) {
	f := newProcessingFixture(t, "1")
	genesis := sourceFile(t, t.TempDir(), "local-genesis.json", []byte(syntheticGenesisConfig))
	f.m.Genesis = &genesis
	f.m.Scopes[0].GenesisSHA = genesis.SHA256
	f.m.Scopes[0].InputRun, f.m.Scopes[0].InputInstance = "synthetic-inputs", "1"
	m := f.write(t)
	inputs := syntheticObservedInputs(t, m, nil)
	m.Inputs = &inputs
	a, err := Assess(t.Context(), m, "1", "1")
	if err != nil || a.Sources.Inputs.DeclaredScopeMatches != 1 || a.CoreExecuted || a.Heights[0].Status == "complete" {
		t.Fatal(a, err)
	}
	for _, change := range []func(*RunScope){
		func(s *RunScope) { s.InputRun = "foreign" },
		func(s *RunScope) { s.InputInstance = "2" },
		func(s *RunScope) { s.InputInstance = "01" },
		func(s *RunScope) { s.InputInstance = "0" },
		func(s *RunScope) { s.InputInstance = "18446744073709551616" },
		func(s *RunScope) { s.FrameRun = "foreign" },
		func(s *RunScope) { s.GenesisSHA = strings.Repeat("9", 64) },
		func(s *RunScope) { s.GenesisSHA = "" },
		func(s *RunScope) { s.From = processingWall(10) },
	} {
		candidate := m
		candidate.Scopes = append([]RunScope{}, m.Scopes...)
		change(&candidate.Scopes[0])
		if _, err := Assess(t.Context(), candidate, "1", "1"); err == nil {
			t.Fatal("foreign or unbound input declaration accepted", candidate.Scopes[0])
		}
	}
}
