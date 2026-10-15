package scenariojob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
)

func transportManifestFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	storage := filepath.Join(t.TempDir(), "objects")
	write := func(id, node string) transportFile {
		raw := []byte(`{"fixture":"storage-only"}`)
		path := filepath.Join(root, id+".json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		return transportFile{ID: id, Node: node, Path: path, SHA: hex.EncodeToString(sum[:])}
	}
	m := transportManifest{Format: "wbft-analyzer-transport-manifest/1", ID: "declaration", Controller: write("controller", "network")}
	m.Network.ChainID = "1"
	m.Network.GenesisHash = "0x" + strings.Repeat("a", 64)
	for i, node := range []string{"0x" + strings.Repeat("1", 40), "0x" + strings.Repeat("2", 40)} {
		id := []string{"first", "second"}[i]
		m.Headers = append(m.Headers, write("headers-"+id, node))
		w := struct {
			Input       string        `json:"input"`
			Certificate transportFile `json:"certificate"`
		}{Input: "frames-" + id, Certificate: write("certificate-"+id, node)}
		m.Windows = append(m.Windows, w)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "manifest.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, storage
}

func TestTransportWitnessObjectsSurviveSourceMutationAndRebase(t *testing.T) {
	path, storage := transportManifestFixture(t)
	ctx := context.Background()
	snapshot, err := retainTransportEvidence(ctx, path, storage, "1", "0x"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	first, err := readTransportEvidence(ctx, *snapshot, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var manifest transportManifest
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(manifest.Controller.Path, []byte(`{"changed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(`{"changed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := readTransportEvidence(ctx, *snapshot, t.TempDir())
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("retained witness read mutable external inputs", err)
	}
	if _, err := retainTransportEvidence(ctx, path, storage, "1", manifest.Network.GenesisHash); err == nil {
		t.Fatal("changed declaration accepted")
	}
	outer := scenario.SourceSnapshot{Transport: snapshot}
	if len(outer.Objects()) != 7 {
		t.Fatal("transport witnesses omitted from source ownership", len(outer.Objects()))
	}
	before, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	rebasedRoot := t.TempDir()
	for _, object := range snapshot.Objects() {
		raw, err := os.ReadFile(object.Path)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(rebasedRoot, object.SHA256), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	rebased := outer.Rebase(rebasedRoot)
	after, err := json.Marshal(outer)
	if err != nil || string(before) != string(after) {
		t.Fatal("rebase mutated source references", err)
	}
	third, err := readTransportEvidence(ctx, *rebased.Transport, t.TempDir())
	if err != nil || !reflect.DeepEqual(first, third) {
		t.Fatal("rebased witness changed", err)
	}
	bad := *snapshot
	bad.Windows = append([]scenario.TransportWindowObject(nil), snapshot.Windows...)
	bad.Windows[0].Input = "unrelated-input"
	if _, err := readTransportEvidence(ctx, bad, t.TempDir()); err == nil {
		t.Fatal("snapshot mapping detached from retained declaration")
	}
	if err = os.WriteFile(snapshot.Controller.File.Path, []byte(`{"corrupt":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTransportEvidence(ctx, *snapshot, t.TempDir()); err == nil {
		t.Fatal("corrupt CAS witness accepted")
	}
}
