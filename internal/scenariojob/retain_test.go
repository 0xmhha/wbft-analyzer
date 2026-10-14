package scenariojob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
)

func TestRetainedEventPrefixPreservesChunkOrderAndRefusesMutation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "input.jsonl")
	prefix := []byte("first\nsecond\nthird\n")
	hash := sha256.Sum256(prefix)
	if err := os.WriteFile(path, append(append([]byte(nil), prefix...), []byte("unfinished")...), 0600); err != nil {
		t.Fatal(err)
	}
	in := logs.PreparedInput{Path: path, Summary: logs.InputSummary{ID: "event", Kind: "events", Node: "node", Bytes: int64(len(prefix)), SHA256: hex.EncodeToString(hash[:])}}
	storage := filepath.Join(root, "objects")
	first, err := retainEventChunks(ctx, in, storage, 8)
	if err != nil || len(first.Files) != 3 {
		t.Fatal(first, err)
	}
	var actual []byte
	for i, ref := range first.Files {
		target := filepath.Join(t.TempDir(), "copy")
		if err := reexec.CopyObject(ctx, ref, target); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		actual = append(actual, data...)
		if ref.Name == "" || i > 0 && ref.Name <= first.Files[i-1].Name {
			t.Fatal("unordered prefix chunks")
		}
	}
	if !bytes.Equal(actual, prefix) {
		t.Fatal("tail included or chunk order changed")
	}
	if err := os.WriteFile(path, append(append([]byte(nil), prefix...), []byte("later appended data\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	next, err := retainEventChunks(ctx, in, storage, 8)
	if err != nil || next.Source.SHA256 != first.Source.SHA256 {
		t.Fatal("append changed immutable prefix", err)
	}
	broken := append([]byte(nil), prefix...)
	broken[0] = 'x'
	if err := os.WriteFile(path, broken, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := retainEventChunks(ctx, in, storage, 8); err == nil {
		t.Fatal("changed prefix accepted")
	}
	if err := os.WriteFile(first.Files[0].Path, []byte("corrupt!"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reexec.CopyObject(ctx, first.Files[0], filepath.Join(t.TempDir(), "corrupt-copy")); err == nil {
		t.Fatal("corrupt retained object accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := retainEventChunks(cancelled, in, storage, 8); err == nil {
		t.Fatal("cancelled archive accepted")
	}
}
