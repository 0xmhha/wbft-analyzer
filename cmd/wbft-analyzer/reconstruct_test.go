package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/reconstruct"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
)

func TestReconstructionCommandKeepsUnavailableHeightsAndRejectsChangedInput(t *testing.T) {
	dir := t.TempDir()
	log := []byte(`{"t":"2020-01-01T00:00:00Z","lvl":"info","msg":"WBFT: start new round","next.seq":"1","next.round":"0"}` + "\n")
	if err := os.WriteFile(filepath.Join(dir, "log.jsonl"), log, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(log)
	m := reconstruct.Manifest{Format: reconstruct.ManifestFormat, Node: "0x1111111111111111111111111111111111111111", Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Log: reconstruct.File{Path: "log.jsonl", SHA256: hex.EncodeToString(hash[:])}}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifest, raw, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"reconstruct", "--manifest", manifest, "--from", "1", "--to", "2"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	var result reconstruct.Assessment
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || len(result.Heights) != 2 || result.Heights[0].Status != "not_possible" || result.Heights[1].Status != "not_possible" || result.CoreExecuted {
		t.Fatal(result, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(append(append([]string{}, args...), "--execute", "--review-position", "1"), &stdout, &stderr); code != exitDataErr || stdout.Len() != 0 {
		t.Fatal("Info-only source manufactured a review step", code, stdout.String(), stderr.String())
	}
	if err := os.WriteFile(filepath.Join(dir, "log.jsonl"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(args, &stdout, &stderr); code != exitDataErr || stdout.Len() != 0 || strings.Contains(stderr.String(), dir) {
		t.Fatal(code, stdout.String(), stderr.String())
	}
}
