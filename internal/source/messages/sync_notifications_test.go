package messages

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func typedSyncFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/sync-notifications/complete.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func rewriteTypedSyncRow(t *testing.T, input string, line int, edit func(map[string]any)) string {
	t.Helper()
	rows := strings.Split(strings.TrimSuffix(input, "\n"), "\n")
	var row map[string]any
	if err := json.Unmarshal([]byte(rows[line-1]), &row); err != nil {
		t.Fatal(err)
	}
	edit(row)
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	rows[line-1] = string(b)
	return strings.Join(rows, "\n") + "\n"
}
func TestTypedSyncSourcePreservesSequenceClockAndExactNumbers(t *testing.T) {
	s, err := parseSyncNotifications(context.Background(), strings.NewReader(typedSyncFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if !s.retainedComplete || s.lines != 8 || s.footerOrdinal != 8 || s.clockRegressions != 1 || s.header.CoreStartSeq != "0" || !s.header.Validator || len(s.notifications) != 6 {
		t.Fatal(s)
	}
	for i, row := range s.notifications {
		if row.ordinal != int64(i+2) {
			t.Fatal(row)
		}
	}
	if s.notifications[3].notification.Number != "9007199254740993" || s.notifications[5].notification.Number != "115792089237316195423570985008687907853269984665640564039457584007913129639935" {
		t.Fatal("completion number lost precision")
	}
	if s.notifications[2].notification.PostedAt != "2025-12-31T23:59:59Z" || s.notifications[1].notification.PostedAtAvailable || s.notifications[1].notification.PostedAt != "" {
		t.Fatal("missing or regressing source time was repaired")
	}
}

func TestTypedSyncSourceRetainsIncompleteFileAndProducerClaimSeparately(t *testing.T) {
	raw := typedSyncFixture(t)
	withoutFooter := raw[:strings.LastIndex(strings.TrimSuffix(raw, "\n"), "\n")+1]
	for name, data := range map[string]string{"missing-footer": withoutFooter, "missing-final-LF": strings.TrimSuffix(raw, "\n"), "aborted": rewriteTypedSyncRow(t, raw, 8, func(r map[string]any) { r["closed_normally"] = false; r["complete"] = false })} {
		t.Run(name, func(t *testing.T) {
			s, err := parseSyncNotifications(context.Background(), strings.NewReader(data))
			if err != nil || s.retainedComplete || len(s.notifications) != 6 {
				t.Fatal(s, err)
			}
			if name == "missing-final-LF" && (s.footer == nil || !s.footer.Complete) {
				t.Fatal("original producer claim was overwritten")
			}
		})
	}
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	loss := strings.Join([]string{lines[0], lines[1], lines[3], lines[7]}, "\n") + "\n"
	loss = rewriteTypedSyncRow(t, loss, 4, func(r map[string]any) {
		r["observed"] = "3"
		r["written"] = "2"
		r["dropped"] = "1"
		r["complete"] = false
	})
	if s, err := parseSyncNotifications(context.Background(), strings.NewReader(loss)); err != nil || s.retainedComplete || s.notifications[1].notification.Sequence != "3" || s.footer.Dropped != "1" {
		t.Fatal(s, err)
	}
}

func TestTypedSyncSourceRejectsMalformedMetadataWithoutCopyingIt(t *testing.T) {
	raw := typedSyncFixture(t)
	for _, test := range []struct {
		name string
		line int
		edit func(map[string]any)
	}{
		{"unsupported-format", 1, func(r map[string]any) { r["format"] = "wbft-sync-notifications/2" }},
		{"case-alias", 1, func(r map[string]any) { r["Validator"] = false }},
		{"foreign-node-shape", 1, func(r map[string]any) { r["node"] = "unknown" }},
		{"noncanonical-node", 1, func(r map[string]any) { r["node"] = "0xAA00000000000000000000000000000000000000" }},
		{"empty-run", 1, func(r map[string]any) { r["run"] = "" }},
		{"wrong-start", 1, func(r map[string]any) { r["core_start_seq"] = "1" }},
		{"numeric-sequence", 2, func(r map[string]any) { r["sequence"] = 1 }},
		{"repeated-sequence", 3, func(r map[string]any) { r["sequence"] = "1" }},
		{"sequence-overflow", 2, func(r map[string]any) { r["sequence"] = "18446744073709551616" }},
		{"noncanonical-sequence", 2, func(r map[string]any) { r["sequence"] = "01" }},
		{"unknown-kind", 2, func(r map[string]any) { r["kind"] = "retry" }},
		{"missing-clock", 2, func(r map[string]any) { delete(r, "posted_at") }},
		{"unknown-clock", 2, func(r map[string]any) { r["posted_at"] = "NEVER_PERSIST_THIS_TEXT" }},
		{"invented-clock", 3, func(r map[string]any) { r["posted_at"] = "2026-01-01T00:00:00Z" }},
		{"invented-monotonic", 2, func(r map[string]any) { r["t_mono_ns"] = "1" }},
		{"noncanonical-clock", 2, func(r map[string]any) { r["posted_at"] = "2026-01-01T00:00:00+00:00" }},
		{"error-text", 3, func(r map[string]any) { r["error"] = "NEVER_PERSIST_THIS_TEXT" }},
		{"invented-completion", 2, func(r map[string]any) { r["number"] = "1" }},
		{"missing-hash", 5, func(r map[string]any) { delete(r, "hash") }},
		{"invalid-hash", 5, func(r map[string]any) { r["hash"] = "NEVER_PERSIST_THIS_TEXT" }},
		{"negative-number", 5, func(r map[string]any) { r["number"] = "-1" }},
		{"number-overflow", 7, func(r map[string]any) {
			r["number"] = "115792089237316195423570985008687907853269984665640564039457584007913129639936"
		}},
		{"wrong-count", 8, func(r map[string]any) { r["written"] = "5" }},
		{"missing-loss-count", 8, func(r map[string]any) { r["observed"] = "7" }},
		{"missing-stop", 8, func(r map[string]any) { delete(r, "core_stop_seq") }},
		{"zero-stop", 8, func(r map[string]any) { r["core_stop_seq"] = "0" }},
		{"contradictory-complete", 8, func(r map[string]any) { r["closed_normally"] = false }},
		{"contradictory-incomplete", 8, func(r map[string]any) { r["complete"] = false }},
		{"invented-exhaustion", 8, func(r map[string]any) { r["sequence_exhausted"] = true; r["complete"] = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, err := parseSyncNotifications(context.Background(), strings.NewReader(rewriteTypedSyncRow(t, raw, test.line, test.edit)))
			if s != nil || !errors.Is(err, errSyncNotifications) || strings.Contains(err.Error(), "NEVER_PERSIST_THIS_TEXT") {
				t.Fatal(s, err)
			}
		})
	}
	for _, fields := range []struct {
		line int
		keys []string
	}{{1, []string{"validator"}}, {2, []string{"posted_at_available"}}, {8, []string{"sequence_exhausted", "core_complete", "closed_normally", "complete"}}} {
		for _, key := range fields.keys {
			for _, null := range []bool{false, true} {
				t.Run(key+map[bool]string{true: "-null", false: "-missing"}[null], func(t *testing.T) {
					data := rewriteTypedSyncRow(t, raw, fields.line, func(r map[string]any) {
						if null {
							r[key] = nil
						} else {
							delete(r, key)
						}
					})
					if s, err := parseSyncNotifications(context.Background(), strings.NewReader(data)); s != nil || !errors.Is(err, errSyncNotifications) {
						t.Fatal(s, err)
					}
				})
			}
		}
	}
	for name, data := range map[string]string{"duplicate-key": strings.Replace(raw, `"validator":true`, `"validator":true,"validator":false`, 1), "trailing-record": raw + "{}\n", "trailing-object": strings.Replace(raw, "\n", " {}\n", 1), "empty": "", "blank-line": "\n" + raw, "no-header": raw[strings.Index(raw, "\n")+1:], "oversize-line": strings.Repeat("x", maxSyncNotificationLine+1), "invalid-utf8": string([]byte{0xff}) + raw} {
		t.Run(name, func(t *testing.T) {
			if s, err := parseSyncNotifications(context.Background(), strings.NewReader(data)); s != nil || !errors.Is(err, errSyncNotifications) {
				t.Fatal(s, err)
			}
		})
	}
}

type unexpectedTypedRead struct{}

func (unexpectedTypedRead) Read([]byte) (int, error) { panic("canceled source must not read") }
func TestTypedSyncSourceHonorsCancellationBeforeReading(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, err := parseSyncNotifications(ctx, unexpectedTypedRead{})
	if s != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(s, err)
	}
}

var _ io.Reader = unexpectedTypedRead{}
