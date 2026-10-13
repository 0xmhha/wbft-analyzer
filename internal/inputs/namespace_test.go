package inputs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func namespace(t *testing.T) Namespace {
	t.Helper()
	root, e := PrivateRoot(filepath.Join(t.TempDir(), "inputs"))
	if e != nil {
		t.Fatal(e)
	}
	token, e := NewToken()
	if e != nil {
		t.Fatal(e)
	}
	n := Namespace{Root: root, Token: token, Owner: strings.Repeat("a", 64)}
	if e = n.Ensure(); e != nil {
		t.Fatal(e)
	}
	return n
}
func TestNamespaceCleanupRetainsProofAndRefusesForeignEntries(t *testing.T) {
	n := namespace(t)
	object := filepath.Join(n.Directory(), strings.Repeat("b", 64))
	if e := os.WriteFile(object, []byte("synthetic object"), 0600); e != nil {
		t.Fatal(e)
	}
	unrelated := filepath.Join(n.Directory(), "unrelated.txt")
	if e := os.WriteFile(unrelated, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := n.Clean(context.Background()); !errors.Is(e, ErrOwnership) {
		t.Fatal(e)
	}
	if _, e := os.Stat(object); e != nil {
		t.Fatal("valid object removed before all entries were checked", e)
	}
	if e := os.Remove(unrelated); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := n.Clean(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := os.Stat(object); e != nil {
		t.Fatal(e)
	}
	if e := n.Clean(context.Background()); e != nil {
		t.Fatal(e)
	}
	count, size, e := n.Inspect()
	if e != nil || count != 0 || size != 0 {
		t.Fatal(count, size, e)
	}
	if e := n.Clean(context.Background()); e != nil {
		t.Fatal("cleanup is not retryable", e)
	}
	if e := n.Verify(); e != nil {
		t.Fatal(e)
	}
}
func TestNamespaceRefusesSymlinksAndChangedOwner(t *testing.T) {
	n := namespace(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if e := os.WriteFile(outside, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(n.Directory(), strings.Repeat("c", 64))
	if e := os.Symlink(outside, link); e != nil {
		t.Fatal(e)
	}
	if e := n.Clean(context.Background()); !errors.Is(e, ErrOwnership) {
		t.Fatal(e)
	}
	if b, e := os.ReadFile(outside); e != nil || string(b) != "keep" {
		t.Fatal(b, e)
	}
	if e := os.Remove(link); e != nil {
		t.Fatal(e)
	}
	foreign := n
	foreign.Owner = strings.Repeat("d", 64)
	if e := foreign.Clean(context.Background()); !errors.Is(e, ErrOwnership) {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(n.Directory(), marker)); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(link, []byte("unclaimed"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := n.Ensure(); !errors.Is(e, ErrOwnership) {
		t.Fatal("existing bytes claimed without marker", e)
	}
}

func TestNamespaceInitializerRetryNeverClaimsExistingObjects(t *testing.T) {
	n := namespace(t)
	if e := os.Remove(filepath.Join(n.Directory(), marker)); e != nil {
		t.Fatal(e)
	}
	pending := filepath.Join(n.Directory(), ".owner-pending-"+strings.Repeat("e", 32))
	if e := os.WriteFile(pending, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := n.Ensure(); e != nil {
		t.Fatal("interrupted marker initialization cannot resume", e)
	}
	if _, e := os.Stat(pending); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
	if e := n.Verify(); e != nil {
		t.Fatal(e)
	}
}
