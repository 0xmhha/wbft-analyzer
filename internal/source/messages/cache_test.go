package messages

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestReadCacheSnapshotSources(t *testing.T) {
	for _, name := range []string{"cache-source", "cache-source-combined"} {
		t.Run(name, func(t *testing.T) {
			in := Input{ID: "cache", Kind: "frames", Node: "0xaa00000000000000000000000000000000000000", Path: "testdata/" + name}
			sum, err := Fingerprint(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			var rows []Record
			_, err = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(r Record) error { rows = append(rows, r); return nil })
			if err != nil {
				t.Fatal("complete cache source rejected", err)
			}
			if len(rows) != 7 {
				t.Fatal("source rows lost", len(rows))
			}
			for _, i := range []int{0, 2} {
				if rows[i].Mono != nil || rows[i].Wall != "" || rows[i].ClockSource != "unavailable" {
					t.Fatal("declaration invented a measured clock", rows[i])
				}
			}
			encoded, err := json.Marshal(rows[6])
			if err != nil {
				t.Fatal(err)
			}
			var actual map[string]json.RawMessage
			if json.Unmarshal(encoded, &actual) != nil || actual["send_attempt"] == nil || actual["cache_evidence"] == nil {
				t.Fatal("queue attempt or exact source link lost", string(encoded))
			}
			if rows[3].Ordinal != 4 || rows[3].Seq != "4" || rows[6].Ordinal != 7 || rows[6].Seq != "7" {
				t.Fatal("original source order was replaced")
			}
		})
	}
}

func cacheFixtureRows(t *testing.T) []map[string]any {
	t.Helper()
	b, err := os.ReadFile("testdata/cache-source/frames-cache-fixture.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) != nil {
			t.Fatal("fixture JSON")
		}
		rows = append(rows, r)
	}
	return rows
}
func readCacheFixture(t *testing.T, rows []map[string]any) ([]Record, error) {
	t.Helper()
	in := Input{ID: "cache", Kind: "frames", Node: "0xaa00000000000000000000000000000000000000", Path: t.TempDir()}
	var out strings.Builder
	for _, r := range rows {
		b, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		out.Write(b)
		out.WriteByte('\n')
	}
	if e := os.WriteFile(filepath.Join(in.Path, "frames-test.jsonl"), []byte(out.String()), 0600); e != nil {
		t.Fatal(e)
	}
	sum, e := Fingerprint(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	var result []Record
	_, e = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(r Record) error { result = append(result, r); return nil })
	return result, e
}

func TestCacheSnapshotRejectsForgedContextAtomically(t *testing.T) {
	for _, name := range []string{"count", "missing declaration", "missing instance", "sequence gap", "duplicate operation", "wrong offset", "wrong segment", "wrong source seq", "other run", "unknown operation field", "missing bool", "null bool", "null trace", "wrong code", "wrong payload", "wrong cause", "unknown top field", "attempt identity unavailable", "incomplete positive link", "position alias", "duplicate attempt peer", "cross-peer attempt context", "suppression clock"} {
		t.Run(name, func(t *testing.T) {
			rs := cacheFixtureRows(t)
			trace := rs[0]["cache_trace"].(map[string]any)
			op := rs[3]["cache_operation"].(map[string]any)
			attempt := rs[6]["send_attempt"].(map[string]any)
			ref := attempt["cache_decision"].(map[string]any)
			switch name {
			case "suppression clock":
				rs[5]["clock_source"] = "recorded"
			case "count":
				trace["operations"] = "3"
			case "missing declaration":
				rs = rs[1:]
			case "missing instance":
				rs = append(rs[:2], rs[3:]...)
			case "sequence gap":
				op["sequence"] = "9"
			case "duplicate operation":
				rs[4]["cache_operation"].(map[string]any)["sequence"] = "1"
			case "wrong offset":
				ref["source_offset"] = "343"
			case "wrong segment":
				ref["source_segment"] = "1"
			case "wrong source seq":
				ref["source_seq"] = "5"
			case "other run":
				rs[3]["run"] = "other"
			case "unknown operation field":
				op["extra"] = "must not be retained"
			case "missing bool":
				delete(op, "known_hit")
			case "null bool":
				op["known_hit"] = nil
			case "null trace":
				rs[0]["cache_trace"] = nil
			case "wrong code":
				op["code"] = "0x14"
			case "wrong payload":
				op["payload_sha256"] = strings.Repeat("a", 64)
			case "wrong cause":
				op["cause"] = "broadcast"
			case "unknown top field":
				rs[3]["extra"] = "must not be retained"
			case "attempt identity unavailable":
				attempt["available"] = false
			case "incomplete positive link":
				trace["complete"] = false
			case "position alias":
				rs[1]["journal_segment"] = 0
				rs[1]["journal_offset"] = 342
			case "duplicate attempt peer", "cross-peer attempt context":
				b, _ := json.Marshal(rs[6])
				var other map[string]any
				_ = json.Unmarshal(b, &other)
				other["seq"] = 8
				other["journal_offset"] = 900
				if name == "cross-peer attempt context" {
					other["peer"] = "0xcc00000000000000000000000000000000000000"
					other["payload_sha256"] = strings.Repeat("a", 64)
				}
				rs = append(rs, other)
			}
			result, err := readCacheFixture(t, rs)
			if err == nil || len(result) != 0 {
				t.Fatal("forged snapshot emitted retained records", name, err, len(result))
			}
		})
	}
}

func TestCacheSnapshotPreservesUnavailableAndActualSuppressedWrite(t *testing.T) {
	for _, name := range []string{"unknown attempt", "incomplete snapshot", "held write"} {
		t.Run(name, func(t *testing.T) {
			rs := cacheFixtureRows(t)
			switch name {
			case "unknown attempt":
				rs[6]["send_attempt"] = map[string]any{"available": false}
			case "incomplete snapshot":
				rs[0]["cache_trace"].(map[string]any)["complete"] = false
				for _, i := range []int{5, 6} {
					var r map[string]any
					if i == 5 {
						r = rs[i]["cache_decision"].(map[string]any)
					} else {
						r = rs[i]["send_attempt"].(map[string]any)["cache_decision"].(map[string]any)
					}
					r["source_available"] = false
					for _, k := range []string{"source_seq", "source_segment", "source_offset"} {
						delete(r, k)
					}
				}
			case "held write":
				rs[6]["cause"] = "relay"
				rs[6]["send_attempt"].(map[string]any)["cache_decision"] = rs[5]["cache_decision"]
			}
			rows, err := readCacheFixture(t, rs)
			if err != nil || len(rows) != 7 {
				t.Fatal(name, err, len(rows))
			}
			if name == "held write" {
				if rows[6].Write != "ok" || rows[6].CacheEvidence == nil || rows[6].CacheEvidence.Operation.Ordinal != 5 {
					t.Fatal("actual held-cache write was hidden", rows[6])
				}
			} else if rows[6].CacheEvidence != nil {
				t.Fatal("unavailable source became an exact link", rows[6])
			}
		})
	}
}

func TestCacheSourceKeepsUint64IdentityAndOriginalOrdinal(t *testing.T) {
	rows := cacheFixtureRows(t)
	const base uint64 = 9007199254740992
	for _, r := range rows {
		r["seq"] = base + uint64(r["seq"].(float64))
		if offset, ok := r["journal_offset"]; ok {
			r["journal_offset"] = base + uint64(offset.(float64))
		}
		for _, name := range []string{"cache_instance", "cache_operation"} {
			if x, ok := r[name].(map[string]any); ok {
				x["instance"] = "18446744073709551615"
			}
		}
		var ref map[string]any
		if x, ok := r["cache_decision"].(map[string]any); ok {
			ref = x
		}
		if x, ok := r["send_attempt"].(map[string]any); ok {
			x["sequence"] = "18446744073709551615"
			ref = x["cache_decision"].(map[string]any)
		}
		if ref != nil {
			ref["instance"] = "18446744073709551615"
			for _, name := range []string{"source_seq", "source_offset"} {
				n, e := strconv.ParseUint(ref[name].(string), 10, 64)
				if e != nil {
					t.Fatal(e)
				}
				ref[name] = number(base + n)
			}
		}
	}
	actual, err := readCacheFixture(t, rows)
	if err != nil {
		t.Fatal(err)
	}
	frame := actual[6]
	if frame.Ordinal != 7 || frame.Seq != "9007199254740999" || frame.SendAttempt.Sequence != "18446744073709551615" || frame.CacheEvidence == nil || frame.CacheEvidence.Operation.Ordinal != 4 || frame.CacheEvidence.Operation.Seq != "9007199254740996" || frame.SendAttempt.Decision.Offset != "9007199254741334" {
		t.Fatal("large source coordinates lost precision", frame)
	}
}
