package scenario

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestEventInputPinsOriginalStream(t *testing.T) {
	raw, err := os.ReadFile("../source/events/testdata/proposer-stop.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	source := Input{ID: "i", Kind: "events", Node: "0x24667eecdc879d40c9396d604ef787f341fff494", SHA256: hex.EncodeToString(sum[:])}
	got, err := InspectEvents(context.Background(), source, bytes.NewReader(raw))
	if err != nil || len(got.Records) == 0 {
		t.Fatalf("input %v", err)
	}
	source.SHA256 = strings.Repeat("a", 64)
	if _, err := InspectEvents(context.Background(), source, bytes.NewReader(raw)); err == nil {
		t.Fatal("changed source bytes accepted")
	}
	source.SHA256 = hex.EncodeToString(sum[:])
	source.Node = "0x0000000000000000000000000000000000000001"
	if _, err := InspectEvents(context.Background(), source, bytes.NewReader(raw)); err == nil {
		t.Fatal("cross-node source accepted")
	}
}

func TestRecordingClockRegressionsRemainDiagnostic(t *testing.T) {
	raw, err := os.ReadFile("../source/events/testdata/proposer-stop.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	var record map[string]json.RawMessage
	if err := json.Unmarshal(lines[2], &record); err != nil {
		t.Fatal(err)
	}
	record["t_mono_ns"] = json.RawMessage(`0`)
	record["t_wall"] = json.RawMessage(`"2020-01-01T00:00:00Z"`)
	lines[2], err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Join(lines, []byte("\n"))
	sum := sha256.Sum256(raw)
	source := Input{ID: "i", Kind: "events", Node: "0x24667eecdc879d40c9396d604ef787f341fff494", SHA256: hex.EncodeToString(sum[:])}
	got, err := InspectEvents(context.Background(), source, bytes.NewReader(raw))
	if err != nil || got.Stats.ClockRegressions == 0 || got.Records[2].Wall != "2020-01-01T00:00:00Z" {
		t.Fatal("clock diagnostic discarded or timestamp corrected", err)
	}
}
