package store

import (
	"errors"
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"testing"
)

func TestMessageExpansionBoundPrecedesProjection(t *testing.T) {
	events := []logs.Event{}
	for i := 0; i < 1000; i++ {
		events = append(events, logs.Event{Node: fmt.Sprint("n", i), Run: "r", Record: event.Record{Src: "event", Kind: event.EngineStart}})
	}
	for i := 0; i < 1001; i++ {
		events = append(events, logs.Event{Node: "n0", Run: "r", Record: event.Record{Src: "event", Kind: event.Send, Fields: map[string]any{"code": "19", "cause": "broadcast", "dedup_key": "synthetic-bytes"}}})
	}
	projection, e := projectMessageEvents(events)
	if !errors.Is(e, ErrPairSource) || len(projection.Endpoints) != 0 {
		t.Fatal("expanded beyond the source cap", len(projection.Endpoints), e)
	}
}
