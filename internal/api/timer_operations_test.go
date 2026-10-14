package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestTimerOperationAPIStoredMetadataAndSource(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	dataset, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "9", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-timer-api", json.RawMessage(`{"clock":{"model":"unknown"}}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = s.PutMessageInput(ctx, dataset.ID, messages.Summary{ID: "timers", Node: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	mono := "20"
	operation := &messages.TimerOperation{Sequence: "9007199254740993", Action: "queued", Source: "core", Output: "3", ArmEngine: "2", ArmStep: "9007199254740994", ArmOutput: "3", EntryMono: "0", Deadline: "10", Kinds: []string{}, Decode: "complete", Timer: "retry", Generation: "4", Height: "9007199254740995", Round: "1", TimeoutSHA256: strings.Repeat("a", 64)}
	record := messages.Record{Input: "timers", File: "synthetic.wal", Ordinal: 1, Seq: "1", Node: "synthetic", Run: "writer", Type: "timer_operation", Mono: &mono, Height: operation.Height, Round: operation.Round, Timer: operation}
	if err = s.PutMessageRecords(ctx, dataset.ID, []messages.Record{record}, 1); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, dataset.ID, 1, ""); err != nil {
		t.Fatal(err)
	}
	client := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages", dataset.NetworkID, dataset.ID)
	var page MessagePage
	if client.do("GET", base+"/records?type=timer_operation&height=9007199254740995", nil, &page) != 200 || len(page.Records) != 1 || page.Records[0].Timer == nil || page.Records[0].Timer.Sequence != "9007199254740993" {
		t.Fatal(page)
	}
	var actual messages.Record
	if client.do("GET", base+"/source?input=timers&file=synthetic.wal&ordinal=1", nil, &actual) != 200 || actual.Timer == nil || actual.Timer.ArmStep != operation.ArmStep || actual.Timer.EntryMono != "0" || actual.Mono == nil || *actual.Mono != "20" {
		t.Fatal(actual)
	}
	raw, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "payload") || strings.Contains(string(raw), "signature") {
		t.Fatal("material exposed", string(raw))
	}
}
