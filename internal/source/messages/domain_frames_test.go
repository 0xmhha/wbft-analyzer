package messages

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/domainprofile"
)

// These are new unsigned JSON rows. A readable legacy prefix must not become
// normalized evidence when a later row declares an unbound chain profile.
func TestNakedFrameDomainMarkersDiscardReadablePrefix(t *testing.T) {
	for _, field := range []string{"signing_profile", "round_change_domain"} {
		for _, value := range []string{`null`, `{}`, `"unavailable"`} {
			dir := t.TempDir()
			prefix := `{"v":1,"type":"conn","node":"0x0000000000000000000000000000000000000001","run":"model","seq":1,"t_wall":"2026-01-01T00:00:00Z","t_mono_ns":0,"peer":"0x0000000000000000000000000000000000000002","event":"attached"}`
			row := fmt.Sprintf(`{"%s":%s}`, field, value)
			if err := os.WriteFile(filepath.Join(dir, "frames-model.jsonl"), []byte(prefix+"\n"+row+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			input := Input{ID: "model", Kind: "frames", Node: self, Path: dir}
			summary, err := Fingerprint(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			emitted := 0
			stats, err := Read(t.Context(), Prepared{Input: input, Summary: summary}, "7", genesis, func(Record) error { emitted++; return nil })
			if !domainprofile.Unsupported(err) || emitted != 0 || stats.Records != 0 {
				t.Fatal("selected source retained a legacy prefix", field, value, stats, emitted, err)
			}
		}
	}
}
