package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/core"
)

func TestExactJSONRejectsAmbiguousInputs(t *testing.T) {
	type item struct {
		Name string `json:"name"`
	}
	type doc struct {
		Items []item `json:"items"`
	}
	for _, raw := range []string{`{"items":[],"items":[]}`, `{"Items":[]}`, `{"items":[{"Name":"x"}]}`, `{"items":[{"name":"x","Name":"y"}]}`, `{"items":[],"extra":1}`, `{"items":[]} {}`, "{\"items\":[{\"name\":\"\xff\"}]}"} {
		var d doc
		if exactJSON([]byte(raw), 1024, &d) == nil {
			t.Fatalf("accepted ambiguous source %q", raw)
		}
	}
	var d doc
	if exactJSON([]byte(`{"items":[{"name":"x"}]}`), 1024, &d) != nil || len(d.Items) != 1 {
		t.Fatal("valid exact fields refused")
	}
	if exactJSON([]byte(`{"items":[]}`), 2, &d) == nil {
		t.Fatal("manifest bound ignored")
	}
}
func TestGenesisMapAliasesAndUnknownConfigRefused(t *testing.T) {
	base := `{"config":{"chainId":7},"gasLimit":"0x100000","difficulty":"0x1","alloc":{"1111111111111111111111111111111111111111":{"balance":"0x1","storage":{"01":"02"}}}}`
	var g core.Genesis
	if exactJSON([]byte(base), MaxSourceBytes, &g) != nil {
		t.Fatal("valid typed genesis refused")
	}
	for _, raw := range []string{
		strings.Replace(base, `"chainId":7`, `"chainId":7,"ChainId":8`, 1),
		strings.Replace(base, `"chainId":7`, `"chainId":7,"unknownFork":1`, 1),
		strings.Replace(base, `"01":"02"`, `"01":"02","0x0001":"03"`, 1),
		strings.Replace(base, `"1111111111111111111111111111111111111111":{"balance":"0x1"`, `"0x1111111111111111111111111111111111111111":{"balance":"0x2"},"1111111111111111111111111111111111111111":{"balance":"0x1"`, 1),
	} {
		if exactJSON([]byte(raw), MaxSourceBytes, &g) == nil {
			t.Fatal("accepted ambiguous genesis")
		}
	}
}
func TestSourceFilesRequireClosedRootAndChecksums(t *testing.T) {
	dir := t.TempDir()
	raw := []byte("original-source")
	if err := os.WriteFile(filepath.Join(dir, "source"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("source", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	r := &sourceReader{ctx: context.Background(), root: root, files: map[string]FileInput{}}
	input := FileInput{Path: "source", SHA256: digest(raw).SHA256}
	if got, _, err := r.read(input); err != nil || string(got) != string(raw) {
		t.Fatal("closed source refused")
	}
	for _, name := range []string{"../source", "..", ".", "link", "directory", "missing", "source/../source", "/source", "source\\file"} {
		bad := input
		bad.Path = name
		if _, _, err := r.read(bad); err == nil {
			t.Errorf("accepted source path %q", name)
		}
	}
	bad := input
	bad.SHA256 = strings.Repeat("0", 64)
	if _, _, err := r.read(bad); err == nil {
		t.Fatal("changed checksum accepted")
	}
	r.readBytes = MaxReadBytes
	if _, _, err := r.read(input); err == nil {
		t.Fatal("aggregate read bound ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.ctx = ctx
	if _, _, err := r.read(input); err == nil {
		t.Fatal("cancelled read accepted")
	}
}
func TestManifestRequiresCompleteCanonicalIndices(t *testing.T) {
	for _, indices := range [][]string{{}, {"1"}, {"0", "2"}, {"0", "01"}, {"0", "0"}, {"18446744073709551616"}} {
		m := Manifest{Format: InputFormat, Node: "0x1111111111111111111111111111111111111111"}
		for _, n := range indices {
			m.Blocks = append(m.Blocks, BlockInput{Index: n})
		}
		raw, _ := json.Marshal(m)
		_, _, _, _, err := loadManifest(context.Background(), raw, nil)
		if err == nil {
			t.Fatal("non-contiguous source accepted")
		}
	}
}
