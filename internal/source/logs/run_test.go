package logs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSnapshotAndManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.log")
	raw := []byte("{\"t\":\"2026-10-13T00:00:00Z\",\"lvl\":\"info\",\"msg\":\"WBFT: start\"}\n{\"partial\":")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	m := Manifest{Format: ManifestFormat, Name: "run", Run: "run", Network: Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Clock: "unknown", Inputs: []File{{ID: "log-1", Node: "n1", Path: path}}}
	p, err := Prepare(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if p.Inputs[0].Summary.Bytes != int64(strings.Index(string(raw), "\n")+1) {
		t.Fatal(p.Inputs)
	}
	if !strings.Contains(string(p.Metadata), `"normalizer":"`+NormalizerVersion+`"`) {
		t.Fatal("missing normalizer identity")
	}
	if strings.Contains(string(p.Metadata), dir) || strings.Contains(string(p.Metadata), "Path") {
		t.Fatal("local input path stored")
	}
	m.Inputs[0].SHA256 = strings.Repeat("0", 64)
	if _, err = Prepare(context.Background(), m); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	m.Inputs[0].SHA256 = ""
	m.Inputs = append(m.Inputs, m.Inputs[0])
	if _, err = Prepare(context.Background(), m); err == nil {
		t.Fatal("duplicate input accepted")
	}
	m.Inputs = m.Inputs[:1]
	m.FromWall = "2026-10-13T00:00:00Z"
	if _, err = Prepare(context.Background(), m); err == nil {
		t.Fatal("half window accepted")
	}
	m.ToWall = "2026-10-13T00:00:01Z"
	p, err = Prepare(context.Background(), m)
	if err != nil || p.Includes("2026-10-13T00:00:02Z") || !p.Includes(m.FromWall) {
		t.Fatal(p, err)
	}
	m.Inputs[0].Path = "node.log"
	b, _ := json.Marshal(m)
	mp := filepath.Join(dir, "manifest.json")
	_ = os.WriteFile(mp, b, 0600)
	got, err := LoadManifest(mp)
	if err != nil || got.Inputs[0].Path != path {
		t.Fatal(got, err)
	}
	_ = os.WriteFile(mp, append(b, []byte(" {}")...), 0600)
	if _, err = LoadManifest(mp); err == nil {
		t.Fatal("trailing manifest accepted")
	}
}
func TestChainbenchManifestDoesNotCopyLaunchSecrets(t *testing.T) {
	dir := t.TempDir()
	raw := `{"formatVersion":3,"keysDir":"SECRET","binary":"SECRET","nodes":[{"label":"node1","logPath":"logs/node1.log","args":["--password","SECRET"]}]}`
	_ = os.WriteFile(filepath.Join(dir, "chain-record.json"), []byte(raw), 0600)
	m, err := Chainbench(dir, "g7", "run", "gstable@740526d03", Network{ChainID: "7"})
	if err != nil || len(m.Inputs) != 1 || m.Inputs[0].ID != "log-1" {
		t.Fatal(m, err)
	}
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("copied launch secrets")
	}
}

func TestHealthMetadataVersionCompatibility(t *testing.T) {
	for _, v := range []string{"wbft-event-normalization/5", "wbft-event-normalization/6", "wbft-event-normalization/7", "wbft-event-normalization/8", EventNormalizer} {
		if !HealthMetadataPreserved(v) {
			t.Fatal("health metadata unavailable")
		}
	}
	for _, v := range []string{"", "wbft-event-normalization/4", "wbft-event-normalization/99"} {
		if HealthMetadataPreserved(v) {
			t.Fatal("unknown metadata declared complete")
		}
	}
}
