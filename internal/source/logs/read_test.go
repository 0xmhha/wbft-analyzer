package logs

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/observe/event"
)

func TestLegacyStreamMetadataAndSource(t *testing.T) {
	p, err := LoadProfile("")
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{
		`{"t":"2026-10-13T00:00:00Z","lvl":"info","msg":"application"}`,
		`{"t":"2026-10-13T00:00:01Z","lvl":"info","msg":"WBFT: start","address":"0x0000000000000000000000000000000000000001"}`,
		`{"t":"2026-10-13T00:00:02Z","lvl":"info","msg":"WBFT: start new round","next.seq":"18446744073709551617","next.round":"340282366920938463463374607431768211456","next.proposer":"0x0000000000000000000000000000000000000001"}`,
		`{"t":"2026-10-13T00:00:03Z","lvl":"debug","msg":"WBFT: accepted PRE-PREPARE message","address":"0x0000000000000000000000000000000000000001"}`,
		`{"t":"2026-10-13T00:00:04Z","lvl":"info","msg":"WBFT: broadcast ROUND-CHANGE message","payload":"DO_NOT_STORE_A","data":{"payload":"DO_NOT_STORE_B"},"err":"DO_NOT_STORE_C","proposal":"DO_NOT_STORE_D","current.sequence":"18446744073709551617","current.round":2}`,
		`{"t":"2026-10-13T00:00:04Z","lvl":"error","msg":"WBFT: invalid validator","payload":"DO_NOT_STORE_E"}`,
		`{"t":"2026-10-13T00:00:04Z","lvl":"error","msg":"WBFT: invalid message event code","data":"DO_NOT_STORE_F"}`,
		`{"t":"2026-10-13T00:00:04Z","lvl":"error","msg":"WBFT: invalid message","data":"DO_NOT_STORE_G"}`,
		`{"t":"2026-10-13T00:00:03Z","lvl":"trace","msg":"WBFT: post backlog event","msg":"DO_NOT_STORE_H"}`,
		`{"t":"2026-10-13T00:00:05Z","lvl":"trace","msg":"WBFT:   - candidates[123]","addr":"0x0000000000000000000000000000000000000001","diligence":9007199254740993}`,
		`{"t":"2026-10-13T00:00:06Z","lvl":"info","msg":"WBFT: stopped"}`,
		`{"t":"2026-10-13T00:00:07Z","lvl":"debug","msg":"WBFT: accepted PRE-PREPARE message","address":"0x0000000000000000000000000000000000000001"}`,
		`{"t":"2026-10-13T00:00:08Z","lvl":"trace","msg":"WBFT: unknown DO_NOT_STORE_I","payload":"DO_NOT_STORE_J"}`,
		`{"t":"2026-10-13T00:00:09Z","lvl":"warn","msg":"WBFT: broadcast COMMIT message"}`,
		`bad DO_NOT_STORE_K`,
		`{"t":"bad DO_NOT_STORE_L","lvl":"info","msg":"WBFT: start new round"}`,
	}
	events := []Event{}
	stats, err := Read(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), p, "node1", "log-1", func(e Event) error { events = append(events, e); return nil })
	if err != nil || stats.Lines != 16 || stats.Events != 11 || stats.Unknown != 2 || stats.Malformed != 2 || stats.ClockRegressions != 1 {
		t.Fatal(stats, err)
	}
	if events[1].Record.Kind != event.RoundEnter || events[1].Record.View.Seq != "18446744073709551617" || events[1].Record.View.Round != "340282366920938463463374607431768211456" {
		t.Fatal(events[1])
	}
	if !events[2].ViewInferred || events[2].Line != 4 || events[2].Run != "log-1:1" {
		t.Fatal(events[2])
	}
	if events[3].Record.Kind != event.Send || events[3].Record.Fields["phase"] != "ROUND-CHANGE" {
		t.Fatal(events[3])
	}
	if events[8].Record.Fields["diligence"] != "9007199254740993" || events[10].Record.View != nil {
		t.Fatal(events)
	}
	raw, _ := json.Marshal(events)
	if strings.Contains(string(raw), "DO_NOT_STORE") {
		t.Fatal("source bytes escaped allowlist")
	}
	if strings.Contains(stats.Diagnostic(), "DO_NOT_STORE") || !strings.Contains(stats.Diagnostic(), "2") {
		t.Fatal(stats.Diagnostic())
	}
}

func TestWBFTProfileAndCancellation(t *testing.T) {
	p, err := LoadProfile("wbft")
	if err != nil {
		t.Fatal(err)
	}
	var timer *Entry
	for i := range p.Entries {
		if p.Entries[i].Kind == event.TimerFire {
			timer = &p.Entries[i]
		}
	}
	if timer == nil {
		t.Fatal("missing event profile")
	}
	b, _ := json.Marshal(map[string]any{"time": "2026-10-13T00:00:00Z", "level": "DEBUG", "module": timer.Module, "msg": timer.Msg, "h": "1", "r": "3", "payload": "secret"})
	// Use the exact generated profile's level spelling.
	levels := map[string]string{"trace": "DEBUG-4", "debug": "DEBUG", "info": "INFO", "warn": "WARN", "error": "ERROR"}
	var obj map[string]any
	_ = json.Unmarshal(b, &obj)
	obj["level"] = levels[timer.Level]
	b, _ = json.Marshal(obj)
	var got Event
	st, err := Read(context.Background(), strings.NewReader(string(b)), p, "w1", "log-1", func(e Event) error { got = e; return nil })
	if err != nil || st.Events != 1 || got.Record.Kind != event.TimerFire || got.Record.View.Round != "3" {
		t.Fatal(st, got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Read(ctx, strings.NewReader(string(b)), p, "w1", "log-1", func(Event) error { t.Fatal("called after cancellation"); return nil }); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestStrictProfileAndObject(t *testing.T) {
	for _, raw := range []string{`{"format":"wbft-log-profile/1","id":"private","entries":[{}]}`, `{"format":"wbft-log-profile/1","id":"gstable@740526d03","entries":[{"kind":"HEALTH","msg":"WBFT: x","level":"info","fields":{"payload":"secret"}}]}`} {
		if _, err := ParseProfile([]byte(raw)); err == nil {
			t.Fatal("accepted malformed profile")
		}
	}
	for _, raw := range []string{`{} {}`, `[]`, `{"t":"a","t":"b"}`} {
		if _, err := object([]byte(raw)); err == nil {
			t.Fatal("accepted malformed object")
		}
	}
}

// An optional real run exercises streaming all seven legacy files without
// retaining source values in memory. It is not a synthetic consensus node.
func TestActualG7Logs(t *testing.T) {
	dir := os.Getenv("WBFT_ANALYZER_G7_LOGS")
	if dir == "" {
		t.Skip("WBFT_ANALYZER_G7_LOGS is not set")
	}
	p, err := LoadProfile("")
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"node1", "node2", "node3", "node4", "node5", "node6", "node7"} {
		f, err := os.Open(dir + "/" + node + ".log")
		if err != nil {
			t.Fatal(err)
		}
		stat, _ := f.Stat()
		st, err := Read(context.Background(), f, p, node, node, func(e Event) error {
			b, _ := json.Marshal(e.Record.Fields)
			if strings.Contains(string(b), "payload") || strings.Contains(string(b), "data") {
				t.Fatal("unsafe metadata")
			}
			return nil
		})
		_ = f.Close()
		t.Log(node, stat.Size(), st)
		if err != nil || st.Unknown != 0 || st.Malformed != 0 || st.Events == 0 {
			t.Fatal(st, err)
		}
	}
}
