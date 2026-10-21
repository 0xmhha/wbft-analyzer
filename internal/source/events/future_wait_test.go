package events

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func TestFutureWaitHealthRetainsExactNormalSourceMetadata(t *testing.T) {
	var buf bytes.Buffer
	writer := event.NewWriter(&buf, types.Address{19: 1}, "normal-wait-1")
	at := event.Stamp{Wall: time.Unix(1700000000, 0)}
	if err := writer.Write(event.Record{Kind: event.NodeStart, Fields: map[string]any{"impl": "wbft", "mode": "embedded", "sign_floor": nil, "wal_recovery": map[string]any{"records": 0, "torn_bytes": 0, "corrupted": 0}}}, at); err != nil {
		t.Fatal(err)
	}
	for i, origin := range []string{"preprepare", "local_reproposal"} {
		at.Mono = time.Duration(i + 1)
		step := uint64(i + 1)
		at.Step = &step
		row := event.Record{Kind: event.Health, View: &event.View{Seq: "18446744073709551616", Round: "1"}, Fields: map[string]any{"what": "future_proposal_wait_exceeded", "h": "18446744073709551616", "hash": "0x" + strings.Repeat("a", 64), "proposal_origin": origin, "wait_ns": "9007199254740993", "limit_ns": "9007199254740992"}}
		if err := writer.Write(row, at); err != nil {
			t.Fatal(err)
		}
	}
	var rows []logs.Event
	stats, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), "0x"+strings.Repeat("0", 39)+"1", "wait-events", func(row logs.Event) error { rows = append(rows, row); return nil })
	if err != nil || stats.Events != 3 || stats.Malformed != 0 || stats.SequenceGaps != 0 || len(rows) != 3 {
		t.Fatal(stats, err)
	}
	for i, row := range rows[1:] {
		origin := []string{"preprepare", "local_reproposal"}[i]
		if row.Line != int64(i+2) || row.Run != "normal-wait-1" || row.Record.View == nil || row.Record.View.Seq != "18446744073709551616" {
			t.Fatal("source coordinates lost", row)
		}
		fields := row.Record.Fields
		for pass := 0; pass < 2; pass++ {
			if fields["what"] != "future_proposal_wait_exceeded" || fields["proposal_origin"] != origin || fields["wait_ns"] != "9007199254740993" || fields["limit_ns"] != "9007199254740992" || fields["h"] != "18446744073709551616" {
				t.Fatal("normal metadata changed", fields)
			}
			raw, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]json.RawMessage
			if err = json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			m["kind"] = json.RawMessage(`"HEALTH"`)
			fields = Metadata(m)
		}
	}
}
