package api

import (
	"context"
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplayAPIHasSourceBoundStateAndWindow(t *testing.T) {
	s := testStore(t)
	b, err := os.ReadFile("../source/events/testdata/proposer-stop.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	m := logs.Manifest{Format: logs.ManifestFormat, Name: "events", Run: "sim", Clock: "shared-host", Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Inputs: []logs.File{{ID: "e1", Node: "0x24667eecdc879d40c9396d604ef787f341fff494", Kind: "events", Path: path}}}
	result, err := ingest.Run(context.Background(), s, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/replay", result.NetworkID, result.DatasetID)
	var window store.ReplayWindow
	if c.do("GET", base+"/window?from_t=2023-11-14T22:13:20Z&to_t=2023-11-14T22:13:30Z", nil, &window) != 200 || len(window.Events) != 405 || len(window.Nodes) != 1 || window.Nodes[0].Levels[0] != "events" {
		t.Fatal(window)
	}
	var state store.ReplayState
	if c.do("GET", base+"/keyframe?node="+m.Inputs[0].Node+"&t=2023-11-14T22:13:30Z", nil, &state) != 200 || state.State.View == nil || state.State.View.Seq != "9" || state.Frame == nil || state.Tail > 1024 {
		t.Fatal(state)
	}
	for _, suffix := range []string{"/keyframe?node=x&t=2023-11-14T22:13:30Z", "/window?from_t=bad&to_t=bad"} {
		code := c.do("GET", base+suffix, nil, nil)
		if code != 400 && code != 404 {
			t.Fatal(suffix, code)
		}
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/999/datasets/%d/replay/window?from_t=2023-11-14T22:13:20Z&to_t=2023-11-14T22:13:30Z", result.DatasetID), nil, nil) != 404 {
		t.Fatal("cross-network replay exposed")
	}
}
