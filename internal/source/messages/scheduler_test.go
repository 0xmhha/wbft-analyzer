package messages

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadMeasuredSchedulerR01(t *testing.T) {
	in := Input{ID: "scheduler", Kind: "frames", Node: "0xaa00000000000000000000000000000000000000", Path: "testdata/scheduler-source"}
	sum, err := Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var rows []Record
	_, err = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(r Record) error { rows = append(rows, r); return nil })
	if err != nil {
		t.Fatal("measured R01 scheduler source unavailable", err)
	}
	if len(rows) != 13 || rows[0].Type != "scheduler_trace" || rows[0].Mono != nil || rows[0].Wall != "" || rows[0].ClockSource != "unavailable" {
		t.Fatal("declaration became measured evidence", rows)
	}
	operations, steps := 0, 0
	for _, r := range rows {
		if r.Journal == nil {
			t.Fatal("original journal position lost", r)
		}
		if r.Type == "timer_operation" {
			operations++
			if r.Timer == nil || r.ClockSource != "recorded" {
				t.Fatal("measured operation lost", r)
			}
		}
		if r.Type == "scheduler_step" {
			steps++
			if r.EntryMono == nil || r.EntryWall == "" {
				t.Fatal("step entry lost", r)
			}
		}
	}
	if operations != 8 || steps != 4 {
		t.Fatal(operations, steps)
	}
}

func TestMeasuredSchedulerRejectsDamagedSnapshot(t *testing.T) {
	cases := []string{"declaration", "truncation", "sequence gap", "duplicate operation", "other run", "other engine shape", "position", "unknown metadata", "wrong clock", "unknown clock", "null clock", "metadata on other type", "missing entry pair", "malformed tail"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/scheduler-source/frames-scheduler-fixture.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				var r map[string]any
				if err = json.Unmarshal([]byte(line), &r); err != nil {
					t.Fatal(err)
				}
				if r["type"] == "scheduler_trace" && name == "declaration" {
					continue
				}
				if r["type"] == "scheduler_step" && r["step"] == float64(4) && name == "truncation" {
					continue
				}
				if r["type"] == "timer_operation" {
					o := r["timer_operation"].(map[string]any)
					if o["sequence"] == "4" {
						switch name {
						case "sequence gap":
							o["sequence"] = "40"
						case "duplicate operation":
							o["sequence"] = "3"
						case "other run":
							r["run"] = "other"
						case "other engine shape":
							r["engine_run"] = 0
						case "position":
							delete(r, "journal_offset")
						case "unknown metadata":
							o["private_data"] = "reject"
						case "wrong clock":
							o["arm_entry_mono_ns"] = "5000000000"
						case "null clock":
							r["t_mono_ns"] = nil
						case "metadata on other type":
							r["type"] = "outcome"
						}
					}
				}
				if r["type"] == "scheduler_trace" && name == "unknown clock" {
					r["clock_source"] = "recorded"
				}
				if r["type"] == "scheduler_step" && name == "missing entry pair" {
					delete(r, "entry_t_wall")
				}
				v, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				out.Write(v)
				out.WriteByte('\n')
			}
			if name == "malformed tail" {
				out.WriteString("{bad-json}\n")
			}
			in := Input{ID: "scheduler", Kind: "frames", Node: "0xaa00000000000000000000000000000000000000", Path: t.TempDir()}
			if err = os.WriteFile(filepath.Join(in.Path, "frames-test.jsonl"), []byte(out.String()), 0600); err != nil {
				t.Fatal(err)
			}
			sum, err := Fingerprint(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			emitted := 0
			_, err = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(Record) error { emitted++; return nil })
			if err == nil || emitted != 0 {
				t.Fatal("damaged source emitted partial metadata", err, emitted)
			}
		})
	}
}
