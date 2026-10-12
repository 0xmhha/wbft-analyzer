package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/derive/replay"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReplayIndexPreciseSeekAndAppendInvalidation(t *testing.T) {
	s, schema := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginRun(ctx, NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "replay", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	in := logs.InputSummary{ID: "i", Node: "n", Profile: "wbft@events-v1", Kind: "events", ProfileSHA256: strings.Repeat("c", 64), SHA256: strings.Repeat("a", 64)}
	if err = s.PutLogInput(ctx, d.ID, in); err != nil {
		t.Fatal(err)
	}
	es := []logs.Event{}
	origin := time.Date(2026, 10, 13, 0, 0, 0, 123456000, time.UTC)
	for i := int64(1); i <= 3000; i++ {
		mono := "0"
		e := logs.Event{Record: event.Record{Kind: event.Backlog, Fields: map[string]any{"op": "push"}, Src: "event"}, Node: "n", Input: "i", Run: "r", Profile: in.Profile, Line: i, Wall: origin.Add(time.Duration(i) * time.Nanosecond).Format(time.RFC3339Nano), Mono: &mono}
		if i == 1 {
			e.Record.Kind = event.RoundEnter
			e.Record.View = &event.View{Seq: "18446744073709551617", Round: "0"}
		}
		es = append(es, e)
	}
	if err = s.PutLogEvents(ctx, d.ID, es, 3000); err != nil {
		t.Fatal(err)
	}
	release()
	// Rebuild also works with a single-connection pool (no hidden second reader).
	u, _ := url.Parse(os.Getenv("WBFT_ANALYZER_TEST_DSN"))
	q := u.Query()
	q.Set("search_path", schema)
	q.Set("pool_max_conns", "1")
	u.RawQuery = q.Encode()
	one, err := Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	limited, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	index, err := one.RebuildReplay(limited, d.ID)
	if err != nil || index.Records != 3000 || index.Frames != 3 {
		t.Fatal(index, err)
	}
	for _, n := range []int{0, 1, 789, 1024, 1501, 2048, 2999, 3000} {
		target := origin.Add(time.Duration(n) * time.Nanosecond)
		got, err := one.ReplayState(ctx, d.ID, "n", target)
		if err != nil {
			t.Fatal(err)
		}
		want := replay.New("n")
		for _, e := range es[:n] {
			replay.Apply(&want, e)
		}
		if !reflect.DeepEqual(got.State, want) || got.Tail > 1024 {
			t.Fatalf("seek %d differs: %v", n, err)
		}
	}
	window, err := one.ReplayWindow(ctx, d.ID, origin.Add(789*time.Nanosecond), origin.Add(791*time.Nanosecond), "n", "", 0)
	if err != nil || len(window.Events) != 3 || window.Events[0].Line != 789 || window.Nodes[0].Initial.State.Latest.Line != 788 {
		t.Fatal(window, err)
	}
	es[0].Line = 3001
	es[0].Wall = origin.Add(4000 * time.Nanosecond).Format(time.RFC3339Nano)
	if err = s.PutLogEvents(ctx, d.ID, es[:1], 3001); err != nil {
		t.Fatal(err)
	}
	if _, err = one.ReplayState(ctx, d.ID, "n", origin.Add(time.Second)); !errors.Is(err, ErrReplayIndex) {
		t.Fatal("stale index accepted", err)
	}
}
