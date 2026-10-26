package events

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
)

func TestBLSRevealStartupUsesPinnedSchema(t *testing.T) {
	lines := bytes.Split(bytes.TrimSpace(fixture(t)), []byte("\n"))
	var start map[string]json.RawMessage
	if err := json.Unmarshal(lines[0], &start); err != nil {
		t.Fatal(err)
	}
	start["rule_activations"] = json.RawMessage(`{"rejectNumberJump":"0","blsRandao":"18446744073709551619"}`)
	var err error
	lines[0], err = json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	stats, err := Read(context.Background(), bytes.NewReader(bytes.Join(lines, []byte("\n"))), "0x24667eecdc879d40c9396d604ef787f341fff494", "reveal-test", func(logs.Event) error { count++; return nil })
	if err != nil || stats.Malformed != 0 || count != len(lines) {
		t.Fatal("configured startup was discarded", stats, err)
	}
}
