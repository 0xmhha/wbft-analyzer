package events

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

func TestBuildLifecycleReaderKeepsExactSafeMetadataAtPersistence(t *testing.T) {
	node := "0x" + strings.Repeat("1", 40)
	common := `{"v":1,"node":"` + node + `","run":"run-1","t_wall":"2026-01-01T00:00:00Z","view":{"seq":"18446744073709551616","round":"0"},"number":"18446744073709551616","build_id":"build-18446744073709551615",`
	raw := common + `"seq":0,"t_mono_ns":0,"kind":"BUILD_HANDOVER","wait_ns":"9007199254740993","parent":"0x` + strings.Repeat("2", 64) + `"}` + "\n" +
		common + `"seq":1,"t_mono_ns":1,"kind":"BUILD_STARTED"}` + "\n" +
		common + `"seq":2,"t_mono_ns":2,"kind":"BUILD_FINISHED","status":"submitted","hash":"0x` + strings.Repeat("3", 64) + `"}` + "\n"
	var rows []logs.Event
	stats, err := Read(context.Background(), strings.NewReader(raw), node, "input", func(x logs.Event) error { rows = append(rows, x); return nil })
	if err != nil || stats.Malformed != 0 || stats.Events != 3 || stats.SequenceGaps != 0 {
		t.Fatal(stats, err)
	}
	for _, row := range rows {
		b, _ := json.Marshal(row.Record.Fields)
		var m map[string]json.RawMessage
		_ = json.Unmarshal(b, &m)
		m["kind"], _ = json.Marshal(row.Record.Kind)
		again := Metadata(m)
		if again["build_id"] != "build-18446744073709551615" || again["number"] != "18446744073709551616" {
			t.Fatal("identity stripped at persistence", again)
		}
		if row.Record.Kind == event.BuildHandover && again["wait_ns"] != "9007199254740993" {
			t.Fatal("wait precision lost", again)
		}
		if row.Record.Kind == event.BuildFinished && again["status"] != "submitted" {
			t.Fatal("completion status lost", again)
		}
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal([]byte(`{"kind":"BUILD_FINISHED","build_id":"unsafe","status":"unexpected","payload":"private","err":"private","data":{"private":true}}`), &m)
	b, _ := json.Marshal(Metadata(m))
	if bytes.Contains(b, []byte("private")) || bytes.Contains(b, []byte("unexpected")) || bytes.Contains(b, []byte("unsafe")) {
		t.Fatal(string(b))
	}
}

func TestApplicationModuleCannotImpersonateNativeBuildObservation(t *testing.T) {
	node := "0x" + strings.Repeat("1", 40)
	raw := `{"v":1,"node":"` + node + `","run":"run-1","seq":0,"t_wall":"2026-01-01T00:00:00Z","t_mono_ns":0,"kind":"BUILD_FINISHED","src":"app","view":{"seq":"1","round":"0"},"number":"1","build_id":"build-1","status":"submitted","hash":"0x` + strings.Repeat("2", 64) + `"}`
	stats, err := Read(context.Background(), strings.NewReader(raw), node, "input", func(logs.Event) error { t.Fatal("module impersonated a reserved node event"); return nil })
	if err != nil || stats.Events != 0 || stats.Malformed != 1 {
		t.Fatal(stats, err)
	}
}
