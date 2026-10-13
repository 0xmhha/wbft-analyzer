package messages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func archivePlan(t *testing.T) Prepared {
	t.Helper()
	data := []byte("synthetic journal input; never a real capture")
	dir := t.TempDir()
	name := "00000000000000000000.wal"
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	return Prepared{Input: Input{ID: "journal", Kind: "journal", Path: dir}, Summary: Summary{Files: []File{{Name: name, Bytes: int64(len(data)), SHA256: hex.EncodeToString(h[:])}}}}
}

func TestArchiveVerifiedObjectsAndConcurrentRetry(t *testing.T) {
	p := archivePlan(t)
	dir := filepath.Join(t.TempDir(), "inputs")
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := Archive(context.Background(), dir, []Prepared{p})
			if err != nil || len(got["journal"]) != 1 {
				t.Error(got, err)
				return
			}
			f := got["journal"][0]
			if f.SHA256 != p.Summary.Files[0].SHA256 || f.Path != filepath.Join(dir, f.SHA256) {
				t.Error(f)
			}
		}()
	}
	wg.Wait()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	path := filepath.Join(dir, p.Summary.Files[0].SHA256)
	if err = os.WriteFile(path, make([]byte, p.Summary.Files[0].Bytes), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Archive(context.Background(), dir, []Prepared{p}); err == nil {
		t.Fatal("corrupt object reused")
	}
	b, _ := os.ReadFile(path)
	if len(b) != int(p.Summary.Files[0].Bytes) || string(b) != string(make([]byte, len(b))) {
		t.Fatal("corrupt object overwritten")
	}
}

func TestArchiveRefusesChangedSourceLinksAndBounds(t *testing.T) {
	p := archivePlan(t)
	dir := filepath.Join(t.TempDir(), "inputs")
	f := p.Summary.Files[0]
	source := filepath.Join(p.Input.Path, f.Name)
	if err := os.WriteFile(source, make([]byte, f.Bytes), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Archive(context.Background(), dir, []Prepared{p}); err == nil {
		t.Fatal("changed source accepted")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("unverified object published", entries)
	}
	p = archivePlan(t)
	if err := os.Symlink(filepath.Join(p.Input.Path, f.Name), filepath.Join(dir, f.SHA256)); err != nil {
		t.Fatal(err)
	}
	if _, err := Archive(context.Background(), dir, []Prepared{p}); err == nil {
		t.Fatal("symlink object accepted")
	}
	p.Summary.Files[0].Bytes = maxArchiveFile + 1
	if _, err := Archive(context.Background(), filepath.Join(t.TempDir(), "inputs"), []Prepared{p}); err == nil {
		t.Fatal("oversized source accepted")
	}
	p = archivePlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Archive(ctx, filepath.Join(t.TempDir(), "inputs"), []Prepared{p}); err != context.Canceled {
		t.Fatal(err)
	}
	public := t.TempDir()
	if err := os.Chmod(public, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Archive(context.Background(), public, []Prepared{p}); err == nil {
		t.Fatal("public directory accepted")
	}
}
