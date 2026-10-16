package logs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestOutOfProfileContextDoesNotInvalidateLegacyLog(t *testing.T) {
	p, err := LoadProfile("gstable@740526d03")
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"t":"2026-01-02T03:04:05Z","lvl":"warn","msg":"receive path health","module":"consensus.msg","h":7,"h":8}` + "\n" + `{"t":"2026-01-02T03:04:06Z","lvl":"info","msg":"WBFT: stopped"}` + "\n"
	var rows []Event
	stats, err := Read(context.Background(), strings.NewReader(raw), p, "node-1", "legacy-node-1", func(e Event) error { rows = append(rows, e); return nil })
	if err != nil || stats.Malformed != 0 || stats.Unknown != 0 || len(rows) != 1 {
		t.Fatalf("unrelated context invalidated selected profile: %v, stats=%+v, events=%d", err, stats, len(rows))
	}
	if stats.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(raw))) {
		t.Fatal("full source bytes were not hashed", stats)
	}
	var metadata map[string]any
	encoded, _ := json.Marshal(stats)
	if json.Unmarshal(encoded, &metadata) != nil || metadata["out_of_profile_duplicate_context"] != float64(1) {
		t.Fatal("ignored context was not disclosed", metadata)
	}
	if stats.Lines != 2 || rows[0].Line != 2 {
		t.Fatal("original source line changed", stats, rows)
	}
}

func TestAmbiguousProfileEnvelopeAndRelevantContextRemainMalformed(t *testing.T) {
	for _, test := range []struct{ name, profile, raw string }{
		{"native-relevant", "wbft", `{"t":"2026-01-02T03:04:05Z","lvl":"warn","msg":"receive path health","module":"consensus.msg","h":7,"h":8}`},
		{"legacy-relevant", "gstable@740526d03", `{"t":"2026-01-02T03:04:05Z","lvl":"info","msg":"WBFT: stopped","h":7,"h":8}`},
		{"duplicate-module", "gstable@740526d03", `{"t":"2026-01-02T03:04:05Z","msg":"unrelated","module":"a","module":"b","h":7,"h":8}`},
		{"duplicate-time", "gstable@740526d03", `{"t":"2026-01-02T03:04:05Z","t":"2026-01-02T03:04:06Z","msg":"unrelated","h":7,"h":8}`},
		{"null-module", "gstable@740526d03", `{"msg":"unrelated","module":null,"h":7,"h":8}`},
		{"invalid-module", "gstable@740526d03", `{"msg":"unrelated","module":7,"h":7,"h":8}`},
		{"missing-phrase", "gstable@740526d03", `{"module":"other","h":7,"h":8}`},
		{"broken-json", "gstable@740526d03", `{"msg":"unrelated","h":7,"h":8`},
		{"trailing-data", "gstable@740526d03", `{"msg":"unrelated","h":7,"h":8} {}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, err := LoadProfile(test.profile)
			if err != nil {
				t.Fatal(err)
			}
			stats, err := Read(context.Background(), strings.NewReader(test.raw+"\n"), p, "node-1", "input-1", func(Event) error { t.Fatal("ambiguous source projected"); return nil })
			if err != nil || stats.Malformed != 1 || stats.OutOfProfileDuplicateContext != 0 {
				t.Fatal("ambiguous source hidden", err, stats)
			}
		})
	}
}
