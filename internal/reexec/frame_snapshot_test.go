package reexec

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func TestFrameSnapshotVerifiesBytesAndRejectsEscapingFileNames(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "frames-safe.jsonl"), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	input := messages.Input{ID: "synthetic", Kind: "frames", Node: "0x0000000000000000000000000000000000000001", Path: root}
	summary, err := messages.Fingerprint(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := messages.Archive(ctx, store, []messages.Prepared{{Input: input, Summary: summary}})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := SnapshotFrames(ctx, summary, refs[input.ID])
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if raw, err := os.ReadFile(filepath.Join(dir, "frames-safe.jsonl")); err != nil || string(raw) != "{}\n" {
		t.Fatal(string(raw), err)
	}
	bad := summary
	bad.Files = append([]messages.File(nil), summary.Files...)
	bad.Files[0].Name = "../outside"
	badRefs := append([]messages.ArchivedFile(nil), refs[input.ID]...)
	badRefs[0].Name = "../outside"
	if _, err = SnapshotFrames(ctx, bad, badRefs); err == nil {
		t.Fatal("escaping frame name accepted")
	}
	if err = os.WriteFile(refs[input.ID][0].Path, []byte("[]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = SnapshotFrames(ctx, summary, refs[input.ID]); err == nil {
		t.Fatal("changed archived bytes accepted")
	}
}
