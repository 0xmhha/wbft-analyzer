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

func TestTransportCacheRequiresExplicitRuntimeModel(t *testing.T) {
	const node = "0x0000000000000000000000000000000000000001"
	const start = `{"v":1,"node":"` + node + `","run":"cache-runtime","seq":0,"t_wall":"2020-01-01T00:00:00Z","t_mono_ns":0,"kind":"NODE_START","impl":"wbft","mode":"standalone","profile":"compat","sign_floor":null,"wal_recovery":{"corrupted":0,"records":0,"torn_bytes":0},"transport_cache":{"profile":"accepted_completed_v1","active":true,"limits":{"receive_pending":"16","receive_per_peer":"8","write_pending":"64","write_per_peer":"16"}}}`
	var rows []logs.Event
	stats, err := events.Read(context.Background(), strings.NewReader(start), node, "policy", func(e logs.Event) error { rows = append(rows, e); return nil })
	if err != nil || stats.Malformed != 0 || len(rows) != 1 {
		t.Fatal("recorded policy unavailable", stats, err)
	}
	if _, err := FitRuntime(node, "policy", rows, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "transport cache runtime model unavailable") {
		t.Fatal("new runtime policy silently became the old cache model", err)
	}
}

func TestUnavailableTransportCacheStillRequiresExplicitRuntimeModel(t *testing.T) {
	const node = "0x0000000000000000000000000000000000000001"
	for _, declaration := range []string{
		`{"profile":"accepted_completed_v1","active":true,"limits":{"receive_pending":"18446744073709551616","receive_per_peer":"8","write_pending":"64","write_per_peer":"16"}}`,
		`{"profile":"accepted_completed_v1","active":true,"limits":{"receive_pending":"16","receive_per_peer":"17","write_pending":"64","write_per_peer":"16"}}`,
	} {
		start := `{"v":1,"node":"` + node + `","run":"unavailable-cache","seq":0,"t_wall":"2020-01-01T00:00:00Z","t_mono_ns":0,"kind":"NODE_START","impl":"wbft","mode":"standalone","profile":"compat","sign_floor":null,"wal_recovery":{"corrupted":0,"records":0,"torn_bytes":0},"transport_cache":` + declaration + `}`
		var rows []logs.Event
		stats, err := events.Read(context.Background(), strings.NewReader(start), node, "policy", func(e logs.Event) error { rows = append(rows, e); return nil })
		if err != nil || stats.Malformed != 0 || len(rows) != 1 {
			t.Fatal("startup record unavailable", stats, err)
		}
		for range 2 {
			if _, err := FitRuntime(node, "policy", rows, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "transport cache runtime model unavailable") {
				t.Fatal("unsupported declaration became the legacy runtime", err)
			}
			raw := map[string]json.RawMessage{"kind": json.RawMessage(`"NODE_START"`)}
			for key, value := range rows[0].Record.Fields {
				raw[key], err = json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
			}
			rows[0].Record.Fields = events.Metadata(raw)
		}
	}
}
