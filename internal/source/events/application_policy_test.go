package events

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
)

func TestApplicationModelDeclarationIsClosedAndSurvivesPersistence(t *testing.T) {
	for _, result := range []string{"failed", "submitted"} {
		var raw map[string]json.RawMessage
		if e := json.Unmarshal(bytes.Split(bytes.TrimSpace(fixture(t)), []byte("\n"))[0], &raw); e != nil {
			t.Fatal(e)
		}
		raw["application_model"] = json.RawMessage(`{"build_queue":"serial-latest","done_result":"` + result + `","assembly_return":"sampled","selection":"callbacks_then_done_then_pending"}`)
		data, e := json.Marshal(raw)
		if e != nil {
			t.Fatal(e)
		}
		rows := []logs.Event{}
		stats, e := Read(context.Background(), bytes.NewReader(data), "0x24667eecdc879d40c9396d604ef787f341fff494", "source", func(x logs.Event) error { rows = append(rows, x); return nil })
		if e != nil || stats.Malformed != 0 || len(rows) != 1 || rows[0].Record.Fields["application_done_result"] != result {
			t.Fatal(stats, rows, e)
		}
		normalized, e := json.Marshal(rows[0].Record.Fields)
		if e != nil {
			t.Fatal(e)
		}
		var flat map[string]json.RawMessage
		if e = json.Unmarshal(normalized, &flat); e != nil {
			t.Fatal(e)
		}
		flat["kind"] = json.RawMessage(`"NODE_START"`)
		again := Metadata(flat)
		if again["application_build_queue"] != "serial-latest" || again["application_done_result"] != result || again["application_assembly_return"] != "sampled" || again["application_selection"] != "callbacks_then_done_then_pending" {
			t.Fatal(again)
		}
		for _, mode := range []string{"unknown", "missing", "null", "extra"} {
			var declaration map[string]any
			if e = json.Unmarshal(raw["application_model"], &declaration); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "unknown":
				declaration["selection"] = "unrecorded"
			case "missing":
				delete(declaration, "done_result")
			case "null":
				declaration["done_result"] = nil
			case "extra":
				declaration["secret"] = "secret"
			}
			raw["application_model"], e = json.Marshal(declaration)
			if e != nil {
				t.Fatal(e)
			}
			data, e = json.Marshal(raw)
			if e != nil {
				t.Fatal(e)
			}
			st, e := Read(context.Background(), bytes.NewReader(data), "0x24667eecdc879d40c9396d604ef787f341fff494", "source", func(logs.Event) error { return nil })
			if e != nil || st.Malformed != 1 || st.Events != 0 {
				t.Fatal(mode, st, e)
			}
			safe, e := json.Marshal(Metadata(raw))
			if e != nil || strings.Contains(string(safe), "secret") {
				t.Fatal(string(safe), e)
			}
			raw["application_model"] = json.RawMessage(`{"build_queue":"serial-latest","done_result":"` + result + `","assembly_return":"sampled","selection":"callbacks_then_done_then_pending"}`)
		}
		raw["kind"] = json.RawMessage(`"STATE"`)
		if Metadata(raw)["application_build_queue"] != nil {
			t.Fatal("declaration applied outside startup")
		}
	}
}
