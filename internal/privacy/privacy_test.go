package privacy

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestLists: the embedded lists parse; the requirement list is that of
// the pinned specification (723 requirements at 1c91f50).
func TestLists(t *testing.T) {
	if err := Check(); err != nil {
		t.Fatal(err)
	}
	if n := Requirements(); n != 723 || !PublicRequirement("WBFT-SM-083") || PublicRequirement("WBFT-SM-999") {
		t.Fatalf("%d requirements", n)
	}
	if c, ok := PublicCatalog("7e2a9c6ba7c8a148f062c79d54d0e28049323bcfb170871c9e494463f2c5cc87"); !ok || c != "c59b1c5" {
		t.Fatalf("catalog: %q %v", c, ok)
	}
}

// TestRequirementsMatchSpec compares the embedded list with the spec/
// directory of a wbft-spec checkout at spec.lock (WBFT_SPEC_DIR).
func TestRequirementsMatchSpec(t *testing.T) {
	dir := os.Getenv("WBFT_SPEC_DIR")
	if dir == "" {
		t.Skip("WBFT_SPEC_DIR is not set")
	}
	ids, err := Extract(filepath.Join(dir, "spec"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids, lines(requirementsTxt)) {
		t.Fatalf("the specification has %d requirements, the embedded list %d; regenerate it with internal/privacy/gen", len(ids), len(lines(requirementsTxt)))
	}
}

// TestExtract reads requirement lines of chapter files only and refuses an
// ID defined twice.
func TestExtract(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("A-01-x.md", "[WBFT-SM-002] text\n see [WBFT-SM-009]\n[WBFT-SM-001] more\n")
	write("README.md", "[WBFT-SM-003] not a chapter\n")
	ids, err := Extract(dir)
	if err != nil || !slices.Equal(ids, []string{"WBFT-SM-001", "WBFT-SM-002"}) {
		t.Fatalf("ids %v, %v", ids, err)
	}
	write("B-02-y.md", "[WBFT-SM-001] again\n")
	if _, err := Extract(dir); err == nil {
		t.Fatal("a duplicate ID was accepted")
	}
}
