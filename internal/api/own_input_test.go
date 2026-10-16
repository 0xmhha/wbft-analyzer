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

func TestOwnInputEvidenceAPIOriginalSources(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	input := messages.Input{ID: "native", Kind: "frames", Node: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", Path: "../source/messages/testdata/own-input-frames"}
	summary, err := messages.Fingerprint(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	var records []messages.Record
	_, err = messages.Read(ctx, messages.Prepared{Input: input, Summary: summary}, "9", "0x"+strings.Repeat("0", 64), func(r messages.Record) error { records = append(records, r); return nil })
	if err != nil {
		t.Fatal(err)
	}
	dataset, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "9", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-own-input", json.RawMessage(`{"clock":{"model":"unknown"}}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = s.PutMessageInput(ctx, dataset.ID, summary); err != nil {
		t.Fatal(err)
	}
	if err = s.PutMessageRecords(ctx, dataset.ID, records, 4); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, dataset.ID, 4, ""); err != nil {
		t.Fatal(err)
	}
	client := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/messages", dataset.NetworkID, dataset.ID)
	var page MessagePage
	if client.do("GET", base+"/records?type=own_input", nil, &page) != 200 || len(page.Records) != 1 || page.Records[0].OwnInput == nil {
		t.Fatal(page)
	}
	var relay messages.Record
	if client.do("GET", base+"/source?input=native&file=frames-own-fixture.jsonl&ordinal=2", nil, &relay) != 200 || relay.OwnInput == nil {
		t.Fatal(relay)
	}
	proof := relay.OwnInput
	if proof.Outcome.Ordinal != 3 || proof.Input.Ordinal != 4 || proof.Step != "7" || proof.EngineRun != "1" || proof.Journal.Offset != "469" || relay.RelayOf != "" {
		t.Fatal(proof, relay)
	}
	for _, point := range []messages.OwnSourcePoint{proof.Outcome, proof.Input} {
		var actual messages.Record
		path := fmt.Sprintf("%s/source?input=%s&file=%s&ordinal=%d", base, point.Input, point.File, point.Ordinal)
		if client.do("GET", path, nil, &actual) != 200 || actual.Seq != point.Seq || actual.Node != relay.Node || actual.Run != relay.Run || actual.Step != proof.Step || actual.EngineRun != proof.EngineRun || actual.OwnInput == nil {
			t.Fatal("original source does not match provenance", point, actual)
		}
	}
	raw, err := json.Marshal(relay)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"payload":`) || strings.Contains(string(raw), `"signature":`) {
		t.Fatal("raw material exposed")
	}
}
