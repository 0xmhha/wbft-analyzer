package reexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHelperSnapshotRefusesChangedExecutable(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	target := filepath.Join(dir, "snapshot")
	raw := []byte("synthetic executable bytes")
	sum := sha256.Sum256(raw)
	expected := hex.EncodeToString(sum[:])
	if err := os.WriteFile(source, raw, 0755); err != nil {
		t.Fatal(err)
	}
	if err := snapshotHelper(context.Background(), source, target, expected); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("changed executable bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(raw) {
		t.Fatal("snapshot changed with source", err)
	}
	if err = snapshotHelper(context.Background(), source, filepath.Join(dir, "refused"), expected); !errors.Is(err, ErrHelper) {
		t.Fatal("changed executable accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = snapshotHelper(ctx, source, filepath.Join(dir, "cancelled"), expected); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled copy continued", err)
	}
}
