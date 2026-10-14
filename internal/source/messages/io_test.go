package messages

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestJournalIOPreservesMeasuredZeroLargeNanosAndOldAbsence(t *testing.T) {
	dir := t.TempDir()
	a := types.Address{19: 1}
	w, e := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Self: a, Run: "synthetic-io", ChainID: big.NewInt(7)})
	if e != nil {
		t.Fatal(e)
	}
	for _, span := range []*journal.IOInterval{nil, {StartMono: 0, EndMono: 9007199254740993, StartWallNs: 1577836800000000100, EndWallNs: 1577836800000000090}} {
		w.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, Mono: 9007199254740994, WallNs: 1577836800000000200, Code: 0x13, Payload: []byte{0xc0}, Write: "ok", IO: span}})
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	in := Input{ID: "journal", Kind: "journal", Node: self, Path: dir}
	sum, e := Fingerprint(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	var xs []Record
	_, e = Read(context.Background(), Prepared{Input: in, Summary: sum}, "7", genesis, func(r Record) error {
		if r.Type == "frame" {
			xs = append(xs, r)
		}
		return nil
	})
	if e != nil || len(xs) != 2 || xs[0].IO != nil || xs[1].IO == nil || xs[1].IO.StartMono != "0" || xs[1].IO.EndMono != "9007199254740993" || xs[1].IO.StartWall != "2020-01-01T00:00:00.0000001Z" || xs[1].IO.EndWall != "2020-01-01T00:00:00.00000009Z" || xs[1].Wall != "2020-01-01T00:00:00.0000002Z" {
		t.Fatal(xs, e)
	}
	b, e := json.Marshal(xs[1])
	if e != nil {
		t.Fatal(e)
	}
	var restored Record
	if e = json.Unmarshal(b, &restored); e != nil || !reflect.DeepEqual(restored.IO, xs[1].IO) {
		t.Fatal("serialized endpoints changed", e)
	}
}

func TestFrameIORejectsInvalidEvidenceAndRetainsClockRegression(t *testing.T) {
	good := `{"start_wall":"2020-01-01T00:00:00.0000001Z","end_wall":"2020-01-01T00:00:00.00000009Z","start_mono_ns":0,"end_mono_ns":9007199254740993}`
	for _, tc := range []struct {
		name, raw, kind, write string
		valid                  bool
	}{
		{"valid", good, "frame", "ok", true}, {"absent", "", "frame", "ok", true}, {"null", "null", "frame", "ok", false}, {"boolean", "true", "frame", "ok", false}, {"missing", `{"start_mono_ns":0}`, "frame", "ok", false}, {"duplicate", `{"start_wall":"2020-01-01T00:00:00Z","end_wall":"2020-01-01T00:00:00Z","start_mono_ns":0,"end_mono_ns":1,"end_mono_ns":2}`, "frame", "ok", false}, {"unattempted", good, "frame", "not_attached", false}, {"misplaced", good, "conn", "", false},
		{"reversed", `{"start_wall":"2020-01-01T00:00:00Z","end_wall":"2020-01-01T00:00:00Z","start_mono_ns":2,"end_mono_ns":1}`, "frame", "ok", false}, {"after_callback", `{"start_wall":"2020-01-01T00:00:00Z","end_wall":"2020-01-01T00:00:00Z","start_mono_ns":0,"end_mono_ns":9007199254740995}`, "frame", "ok", false}, {"overflow", `{"start_wall":"2020-01-01T00:00:00Z","end_wall":"2020-01-01T00:00:00Z","start_mono_ns":0,"end_mono_ns":9223372036854775808}`, "frame", "ok", false}, {"unknown", `{"start_wall":"2020-01-01T00:00:00Z","end_wall":"2020-01-01T00:00:00Z","start_mono_ns":0,"end_mono_ns":1,"corrected":true}`, "frame", "ok", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mono := int64(9007199254740994)
			x := frameRecord{Type: tc.kind, Dir: "out", Mono: &mono, IO: json.RawMessage(tc.raw)}
			span, e := frameIOInterval(x, tc.write)
			if (e == nil) != tc.valid {
				t.Fatal(span, e)
			}
			if tc.name == "valid" && (span.StartMono != "0" || span.EndMono != "9007199254740993" || span.EndWall != "2020-01-01T00:00:00.00000009Z") {
				t.Fatal(span)
			}
		})
	}
	// Exercise the complete frame reader, including its exact source selector.
	dir := t.TempDir()
	p := filepath.Join(dir, "frames-synthetic.jsonl")
	raw := `{"v":1,"type":"frame","node":"` + self + `","run":"synthetic","seq":0,"t_wall":"2020-01-01T00:00:00.0000002Z","t_mono_ns":9007199254740994,"dir":"out","peer":null,"code":"0x13","wire_code":19,"size":0,"dedup_key":"","write_result":"ok","io":` + good + `}`
	if e := os.WriteFile(p, []byte(raw+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	in := Input{ID: "frames", Kind: "frames", Node: self, Path: dir}
	sum, e := Fingerprint(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	var xs []Record
	_, e = Read(context.Background(), Prepared{Input: in, Summary: sum}, "7", genesis, func(r Record) error { xs = append(xs, r); return nil })
	if e != nil || len(xs) != 1 || xs[0].IO == nil || xs[0].Ordinal != 1 || xs[0].Seq != "0" || xs[0].File != "frames-synthetic.jsonl" || xs[0].Mono == nil || *xs[0].Mono != "9007199254740994" {
		t.Fatal(xs, e)
	}
	start, e := time.Parse(time.RFC3339Nano, xs[0].IO.StartWall)
	if e != nil {
		t.Fatal(e)
	}
	end, e := time.Parse(time.RFC3339Nano, xs[0].IO.EndWall)
	if e != nil || !end.Before(start) {
		t.Fatal("wall clock regression corrected", e)
	}
}
