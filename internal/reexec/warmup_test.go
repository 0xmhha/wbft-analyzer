package reexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func warmupPlan(t *testing.T) Plan {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000000.wal"), []byte("synthetic warmup input"), 0600); err != nil {
		t.Fatal(err)
	}
	in := messages.Input{ID: "journal", Kind: "journal", Path: dir}
	sum, err := messages.Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("synthetic canonical fingerprint")
	chain := filepath.Join(t.TempDir(), "chain.rlp")
	if err = os.WriteFile(chain, raw, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	a := Step{Ordinal: 12, Run: "synthetic-source", Engine: "18446744073709551615", Number: "1", Input: "start", Height: "1", Recorded: "0x" + strings.Repeat("b", 64), Completeness: "complete", Issues: []string{}}
	b := a
	b.Ordinal = 20
	b.Number = "2"
	b.Input = "timer"
	b.Height = "2"
	return Plan{Input: messages.Prepared{Input: in, Summary: sum}, Chain: chain, ChainSHA: hex.EncodeToString(h[:]), SourceVersions: []string{}, Heights: []Height{{Number: "2", Status: "complete", Steps: 1, Issues: []string{}}}, Steps: []Step{a, b}}
}

func TestWarmupMismatchAndCompletenessProtectSelectedRange(t *testing.T) {
	for _, tc := range []struct{ mode, completeness, status, warm string }{
		{"warmup_valid", "complete", "regression", "complete"},
		{"warmup_diverged", "complete", "diverged", "diverged"},
		{"warmup_valid", "partial", "partial", "partial"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			p := warmupPlan(t)
			p.Steps[0].Completeness = tc.completeness
			var got []Step
			r, err := Execute(context.Background(), p, testHelper(t, tc.mode), func(s Step) error { got = append(got, s); return nil })
			if err != nil || r.Status != tc.status || r.Matches != 1 || r.Mismatches != 0 || len(got) != 1 || got[0].Ordinal != 20 {
				t.Fatal("selected range changed", r, got, err)
			}
			w := r.Warmup
			if w == nil || w.Status != tc.warm || w.Steps != 1 || w.FirstSource == nil || *w.FirstSource != 12 || w.LastSource == nil || *w.LastSource != 12 {
				t.Fatal(w)
			}
			if tc.warm != "complete" && (w.FirstDifference == nil || w.FirstDifference.Ordinal != 12 || r.Issue == "") {
				t.Fatal("prefix evidence missing", r)
			}
		})
	}
}

func TestWarmupProtocolAndFailedSource(t *testing.T) {
	p := warmupPlan(t)
	if _, err := Execute(context.Background(), p, testHelper(t, "warmup_bad_digest"), func(Step) error { t.Fatal("invalid prefix reached selection"); return nil }); err == nil {
		t.Fatal("inconsistent prefix match accepted")
	}
	r, err := Execute(context.Background(), p, testHelper(t, "warmup_error"), func(Step) error { t.Fatal("warmup failure counted as selected"); return nil })
	if err == nil || r.Status != "failed" || r.Total != 0 || r.Warmup == nil || r.Warmup.Status != "failed" || r.Warmup.FirstDifference == nil || r.Warmup.FirstDifference.Ordinal != 12 || r.Warmup.FirstDifference.Class != "env_exhausted" {
		t.Fatal(r, err)
	}
}

func TestNewWriterWithoutRecordedStartIsNotExpectedFromHelper(t *testing.T) {
	p := warmupPlan(t)
	tail := p.Steps[1]
	tail.Run = "new-writer-without-start"
	tail.Ordinal = 30
	tail.Height = "3"
	tail.Number = "1"
	p.Steps = append(p.Steps, tail)
	r, err := Execute(context.Background(), p, testHelper(t, "warmup_valid"), func(Step) error { return nil })
	if err != nil || r.Matches != 1 || r.Warmup == nil || r.Warmup.Status != "complete" {
		t.Fatal("missing writer start was treated as replayed", r, err)
	}
}
