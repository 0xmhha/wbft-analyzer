package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestReplayEventEndpointScopeAndStrictQuery(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, e := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "journal", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	if e = s.PutMessageInput(ctx, d.ID, messages.Summary{ID: "journal", Kind: "journal", Node: "node", SHA256: strings.Repeat("a", 64)}); e != nil {
		t.Fatal(e)
	}
	id, e := s.BeginReexec(ctx, d.ID, "journal", "1", "1", "private", reexec.Result{Status: "running", SourceSHA: strings.Repeat("a", 64)})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.PutReexecStep(ctx, id, reexec.Step{Ordinal: 2, File: "00000000000000000000.wal", Run: "writer", Engine: "1", Number: "2", Height: "1", Class: "match"}); e != nil {
		t.Fatal(e)
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/reexec/%d/events", d.NetworkID, d.ID, id)
	var got store.ReexecEventEvidence
	if c.do("GET", base+"?ordinal=2&event_dataset=99", nil, &got) != 200 || got.Status != "unavailable" || got.Reason != "source_unavailable" || len(got.Events) != 0 {
		t.Fatal(got)
	}
	for _, q := range []string{"", "?ordinal=0&event_dataset=1", "?ordinal=2&event_dataset=-1", "?ordinal=2&ordinal=3&event_dataset=1", "?ordinal=2&event_dataset=1&unknown=1", "?ordinal=2.0&event_dataset=1", "?ordinal=9223372036854775808&event_dataset=1"} {
		if code := c.do("GET", base+q, nil, nil); code != 400 {
			t.Fatal(q, code)
		}
	}
	if code := c.do("GET", base+"?ordinal=9&event_dataset=1", nil, nil); code != 404 {
		t.Fatal(code)
	}
	wrong := fmt.Sprintf("/v1/networks/%d/datasets/%d/reexec/%d/events?ordinal=2&event_dataset=1", d.NetworkID+1, d.ID, id)
	if code := c.do("GET", wrong, nil, nil); code != 404 {
		t.Fatal(code)
	}
}
