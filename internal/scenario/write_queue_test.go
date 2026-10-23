package scenario

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/events"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
)

func TestSimulatedWriteQueueRequiresExplicitRuntimeModel(t *testing.T) {
	const node = "0x0000000000000000000000000000000000000001"
	const start = `{"v":1,"node":"` + node + `","run":"write-model","seq":0,"t_wall":"2020-01-01T00:00:00Z","t_mono_ns":0,"kind":"NODE_START","impl":"wbft","mode":"standalone","profile":"compat","sign_floor":null,"wal_recovery":{"corrupted":0,"records":0,"torn_bytes":0},"write_queue_model":{"profile":"simulated_v1","waiting_entries":2,"write_time_ns":"9007199254740993","link_delay":"scenario","completion":"simulated_local_write","cache_policy":"legacy"}}`
	var rows []logs.Event
	stats, err := events.Read(context.Background(), strings.NewReader(start), node, "writes", func(e logs.Event) error { rows = append(rows, e); return nil })
	if err != nil || stats.Malformed != 0 || len(rows) != 1 {
		t.Fatal("simulation declaration unavailable", stats, err)
	}
	for range 2 {
		if _, err := FitRuntime(node, "writes", rows, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "simulated write queue runtime model unavailable") {
			t.Fatal("new simulation silently became the legacy immediate-write model", err)
		}
		raw := map[string]json.RawMessage{"kind": json.RawMessage(`"NODE_START"`)}
		for k, v := range rows[0].Record.Fields {
			raw[k], err = json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
		}
		rows[0].Record.Fields = events.Metadata(raw)
		if rows[0].Record.Fields["write_queue_model"] != "declared" {
			t.Fatal("persistence erased explicit runtime refusal")
		}
	}
}
