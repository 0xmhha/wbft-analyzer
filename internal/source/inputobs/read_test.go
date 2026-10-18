package inputobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func observationFixture() []map[string]any {
	sum := sha256.Sum256([]byte{1, 2, 3})
	rows := []map[string]any{
		{"type": "capture_start", "format": Format, "node": "0x" + strings.Repeat("1", 40), "run": "synthetic-inputs", "frame_run": "synthetic-frames", "genesis_sha256": strings.Repeat("2", 64), "binary_sha256": strings.Repeat("3", 64), "source_commit": strings.Repeat("4", 40)},
		{"type": "begin", "ordinal": "1", "instance": "1", "kind": "start"},
		{"type": "end", "ordinal": "1", "instance": "1", "height": "18446744073709551617", "round": "0", "state": "Accept request"},
		{"type": "begin", "ordinal": "2", "instance": "1", "kind": "message", "code": "19", "peer": "0x" + strings.Repeat("5", 40), "peer_known": true, "payload_available": true, "payload_sha256": hex.EncodeToString(sum[:]), "payload": "0x010203", "height": "18446744073709551617", "round": "0", "state": "Accept request"},
		{"type": "end", "ordinal": "2", "instance": "1", "height": "18446744073709551617", "round": "0", "state": "Accept request"},
		{"type": "capture_end", "dropped": "0"},
	}
	for _, row := range rows {
		if row["height"] != nil {
			row["proposer"] = "0x" + strings.Repeat("1", 40)
			row["valset_digest"] = "0x" + strings.Repeat("6", 64)
			row["config"] = map[string]any{"request_timeout_ms": "2000", "block_period_seconds": "1", "epoch": "10", "max_request_timeout_seconds": "0", "allowed_future_block_seconds": "0", "proposer_policy": "0"}
		}
	}
	stampObservations(rows)
	return rows
}
func stampObservations(rows []map[string]any) {
	for i, row := range rows {
		row["sequence"] = strconv.Itoa(i + 1)
		row["t_mono_ns"] = strconv.Itoa(i)
		row["t_wall"] = time.Date(2020, 1, 1, 0, 0, 0, i, time.UTC).Format(time.RFC3339Nano)
	}
}
func encodeObservations(t *testing.T, rows []map[string]any) []byte {
	t.Helper()
	var data bytes.Buffer
	for _, row := range rows {
		if err := json.NewEncoder(&data).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	return data.Bytes()
}
func hasGap(c Capture, reason string) bool {
	for _, s := range c.Unavailable {
		if s == reason {
			return true
		}
	}
	return false
}

func TestClosedInputObservationStreamKeepsOriginalCoordinatesAndPrivateBytes(t *testing.T) {
	raw := append([]byte("\n"), encodeObservations(t, observationFixture())...)
	c, err := Read(t.Context(), bytes.NewReader(raw))
	sum := sha256.Sum256(raw)
	if err != nil || !c.Complete || c.SHA256 != hex.EncodeToString(sum[:]) || c.Bytes != int64(len(raw)) || len(c.Inputs) != 2 {
		t.Fatal(c, err)
	}
	input := c.Inputs[1]
	if input.BeginLine != 5 || input.EndLine != 6 || input.BeginMono != "3" || input.EndMono != "4" || input.Before.Height != "18446744073709551617" || input.Ordinal != "2" || !bytes.Equal(input.Payload, []byte{1, 2, 3}) {
		t.Fatal(input)
	}
	encoded, _ := json.Marshal(c)
	if bytes.Contains(encoded, []byte("0x010203")) || bytes.Contains(encoded, []byte(`"Payload"`)) {
		t.Fatal("raw input escaped into capture projection")
	}
}

func TestInputObservationGapsNeverBecomeComplete(t *testing.T) {
	for _, test := range []struct {
		name, gap string
		change    func([]map[string]any) []map[string]any
	}{
		{"missing closure", "capture_end_unavailable", func(r []map[string]any) []map[string]any { return r[:5] }},
		{"unfinished input", "open_inputs", func(r []map[string]any) []map[string]any { return append(r[:4], r[5]) }},
		{"dropped records", "dropped_records", func(r []map[string]any) []map[string]any { r[5]["dropped"] = "1"; return r }},
		{"unknown peer", "message_peer_unavailable", func(r []map[string]any) []map[string]any { r[3]["peer_known"] = false; delete(r[3], "peer"); return r }},
		{"unknown payload", "input_payload_unavailable", func(r []map[string]any) []map[string]any {
			r[3]["payload_available"] = false
			delete(r[3], "payload")
			delete(r[3], "payload_sha256")
			return r
		}},
		{"unknown configuration", "configuration_unavailable", func(r []map[string]any) []map[string]any { delete(r[3], "config"); return r }},
		{"unknown validators", "validator_context_unavailable", func(r []map[string]any) []map[string]any { delete(r[3], "valset_digest"); return r }},
		{"unknown input view", "input_view_unavailable", func(r []map[string]any) []map[string]any {
			for _, key := range []string{"height", "round", "state", "config", "valset_digest", "proposer"} {
				delete(r[3], key)
			}
			return r
		}},
		{"unknown resulting view", "input_view_unavailable", func(r []map[string]any) []map[string]any {
			for _, key := range []string{"height", "round", "state", "config", "valset_digest", "proposer"} {
				delete(r[4], key)
			}
			return r
		}},
		{"clock regression", "clock_regression", func(r []map[string]any) []map[string]any { r[3]["t_mono_ns"] = "0"; return r }},
		{"overlapping input", "overlapping_inputs", func(r []map[string]any) []map[string]any {
			x := []map[string]any{r[0], r[1], r[3], r[4], r[2], r[5]}
			stampObservations(x)
			return x
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := encodeObservations(t, test.change(observationFixture()))
			c, err := Read(t.Context(), bytes.NewReader(raw))
			if err != nil || c.Complete || !hasGap(c, test.gap) {
				t.Fatal(c, err)
			}
		})
	}
}

func TestObservationSourceOrdinalsStayFullWidthAcrossGaps(t *testing.T) {
	r := observationFixture()
	r[3]["ordinal"], r[4]["ordinal"] = "9007199254740993", "9007199254740993"
	for i := 3; i < len(r); i++ {
		r[i]["sequence"] = strconv.FormatUint(9007199254740993+uint64(i-3), 10)
		r[i]["t_mono_ns"] = strconv.FormatUint(9007199254740993+uint64(i-3), 10)
	}
	c, err := Read(t.Context(), bytes.NewReader(encodeObservations(t, r)))
	if err != nil || c.Complete || c.Inputs[1].Ordinal != "9007199254740993" || c.Inputs[1].BeginMono != "9007199254740993" || c.Inputs[1].EndMono != "9007199254740994" || !hasGap(c, "sequence_gap") || !hasGap(c, "input_ordinal_gap") {
		t.Fatal(c, err)
	}
}

func TestInputObservationsRejectContradictionsWithoutPartialCapture(t *testing.T) {
	for _, change := range []func([]map[string]any){
		func(r []map[string]any) { r[3]["payload"] = "0x040506" },
		func(r []map[string]any) { r[3]["code"] = "18446744073709551616" },
		func(r []map[string]any) { r[3]["peer"] = "unknown" },
		func(r []map[string]any) { r[3]["state"] = "invented" },
		func(r []map[string]any) { r[3]["kind"] = "invented" },
		func(r []map[string]any) { r[4]["ordinal"] = "3" },
		func(r []map[string]any) { r[4]["instance"] = "2" },
		func(r []map[string]any) { r[4]["kind"] = "message" },
		func(r []map[string]any) { r[0]["payload"] = "PRIVATE_VALUE" },
		func(r []map[string]any) { r[3]["source_url"] = "PRIVATE_VALUE" },
	} {
		r := observationFixture()
		change(r)
		c, err := Read(t.Context(), bytes.NewReader(encodeObservations(t, r)))
		if err == nil || len(c.Inputs) != 0 || c.Node != "" {
			t.Fatal("invalid capture exposed partial data", c, err)
		}
	}
	raw := encodeObservations(t, observationFixture())
	raw = bytes.Replace(raw, []byte(`"code":"19"`), []byte(`"code":"19","code":"19"`), 1)
	if _, err := Read(t.Context(), bytes.NewReader(raw)); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestInputObservationResourceBoundsAndCancellation(t *testing.T) {
	raw := encodeObservations(t, observationFixture())
	if c, err := read(t.Context(), bytes.NewReader(raw), len(raw), 2); err != nil || !c.Complete {
		t.Fatal(c, err)
	}
	if c, err := read(t.Context(), bytes.NewReader(raw), len(raw)-1, 2); err == nil || len(c.Inputs) != 0 {
		t.Fatal("byte bound exposed partial capture", c, err)
	}
	if _, err := read(t.Context(), bytes.NewReader(raw), len(raw), 1); err == nil {
		t.Fatal("input bound bypassed")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Read(ctx, bytes.NewReader(raw)); err != context.Canceled {
		t.Fatal(err)
	}
}
