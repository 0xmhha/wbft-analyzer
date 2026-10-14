package scenariojob

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
)

func TestRuntimeRetentionRefusesChangedBytesAndRebasesOwnedObjects(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	input := filepath.Join(root, "runtime.jsonl")
	raw, e := os.ReadFile("../source/runtimeobs/testdata/synthetic.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(input, raw, 0600); e != nil {
		t.Fatal(e)
	}
	c, e := runtimeobs.Load(input)
	if e != nil {
		t.Fatal(e)
	}
	m := runtimeManifest{Format: "wbft-analyzer-runtime-manifest/1", Network: logs.Network{ChainID: "8", GenesisHash: "genesis"}, Inputs: []runtimeFile{{ID: "runtime", Node: c.Node, Path: "runtime.jsonl", SHA: c.SourceSHA}}}
	body, _ := json.Marshal(m)
	manifest := filepath.Join(root, "manifest.json")
	if e = os.WriteFile(manifest, body, 0600); e != nil {
		t.Fatal(e)
	}
	objects, e := retainRuntimeObservations(ctx, manifest, filepath.Join(root, "objects"), "8", "genesis")
	if e != nil || len(objects) != 1 || objects[0].Source.SHA256 != c.SourceSHA {
		t.Fatal(objects, e)
	}
	snapshot := scenario.SourceSnapshot{Runtime: objects}
	rebased := snapshot.Rebase("/owned")
	if rebased.Runtime[0].File.Path != filepath.Join("/owned", c.SourceSHA) || objects[0].File.Path == rebased.Runtime[0].File.Path {
		t.Fatal("rebase mutated original")
	}
	copy := filepath.Join(root, "copy")
	if e = reexec.CopyObject(ctx, objects[0].File, copy); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(input, append(raw, []byte(" ")...), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = retainRuntimeObservations(ctx, manifest, filepath.Join(root, "objects"), "8", "genesis"); e == nil {
		t.Fatal("mutated source accepted")
	}
	if _, e = retainRuntimeObservations(ctx, manifest, filepath.Join(root, "objects"), "9", "genesis"); e == nil {
		t.Fatal("foreign declaration accepted")
	}
}
