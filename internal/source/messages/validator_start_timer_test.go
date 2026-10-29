package messages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestValidatorStartWaitRetainsNativeJournalAndSnapshotMetadata(t *testing.T) {
	dir := t.TempDir()
	node := types.Address{19: 1}
	writer, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Self: node, Run: "synthetic-validator-start", ChainID: big.NewInt(7), Core: journal.CoreOptions{TimerTrace: 1, Improvements: uint64(consensus.RestartSafety.With(consensus.DeferValidatorStart))}})
	if err != nil {
		t.Fatal(err)
	}
	input, err := inputlog.Encode(consensus.Timeout{Kind: consensus.ValidatorStartTimer, Gen: 9007199254740993, View: types.View{Sequence: types.HeightFromUint64(9007199254740994), Round: types.RoundFromUint64(3)}})
	if err != nil {
		t.Fatal(err)
	}
	writer.Put(journal.Record{Body: &journal.TimerRec{Sequence: 1, EngineRun: 2, Step: 7, Output: 3, ArmEngineRun: 2, ArmStep: 7, ArmOutput: 3, Source: "core", Action: "arm", Mono: 20, WallNs: 1577836800000000020, EntryMono: 0, Deadline: 30, Input: input}})
	writer.Put(journal.Record{Body: &journal.TimerRec{Sequence: 2, EngineRun: 2, Step: 8, Output: 2, Source: "core", Action: "cancel", Mono: 21, WallNs: 1577836800000000021, Kinds: []uint64{0, 1, 2, 3, 4}}})
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	in := Input{ID: "timers", Kind: "journal", Node: self, Path: dir}
	summary, err := Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var projected []Record
	_, err = Read(context.Background(), Prepared{Input: in, Summary: summary}, "7", genesis, func(r Record) error { projected = append(projected, r); return nil })
	if err != nil {
		t.Fatal(err)
	}
	var ops []Record
	for _, record := range projected {
		if record.Type == "segment" && record.TimerTrace != "1" {
			t.Fatal("capability lost", record)
		}
		if record.Type == "timer_operation" {
			ops = append(ops, record)
		}
	}
	sum := sha256.Sum256(input)
	if len(ops) != 2 || ops[0].Timer == nil || ops[0].Timer.Sequence != "1" || ops[0].Timer.Timer != "validator_start" || ops[0].Timer.Generation != "9007199254740993" || ops[0].Timer.Height != "9007199254740994" || ops[0].Timer.TimeoutSHA256 != hex.EncodeToString(sum[:]) || ops[0].Timer.EntryMono != "0" || ops[0].Mono == nil || *ops[0].Mono != "20" || ops[0].Timer.Decode != "complete" {
		t.Fatal("precise evidence lost", ops)
	}
	if ops[1].Timer == nil || len(ops[1].Timer.Kinds) != 5 || ops[1].Timer.Kinds[4] != "validator_start" || ops[1].Timer.Decode != "not_applicable" {
		t.Fatal("cancel evidence lost", ops[1])
	}
	encoded, err := json.Marshal(ops)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "payload") || strings.Contains(string(encoded), "signature") || strings.Contains(string(encoded), "\"Input\"") {
		t.Fatal("input material crossed projection boundary", string(encoded))
	}

	snapshot := Input{ID: "validator-start-snapshot", Kind: "frames", Node: self, Path: t.TempDir()}
	var frames strings.Builder
	rows := []map[string]any{{"v": 1, "type": "scheduler_trace", "node": self, "run": "validator-start-snapshot", "seq": 1, "t_wall": "1970-01-01T00:00:00Z", "t_mono_ns": 0, "journal_segment": 0, "journal_offset": 0, "clock_source": "unavailable", "scheduler_trace": map[string]string{"version": "1", "operations": "2", "steps": "0"}}}
	for i, record := range ops {
		rows = append(rows, map[string]any{"v": 1, "type": "timer_operation", "node": self, "run": "validator-start-snapshot", "seq": i + 2, "t_wall": "2020-01-01T00:00:00.000000021Z", "t_mono_ns": 21, "journal_segment": 0, "journal_offset": i + 1, "engine_run": 2, "step": i + 7, "timer_operation": record.Timer})
	}
	for _, row := range rows {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		frames.Write(raw)
		frames.WriteByte('\n')
	}
	if err = os.WriteFile(filepath.Join(snapshot.Path, "frames-local-wait.jsonl"), []byte(frames.String()), 0600); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := Fingerprint(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var retained []Record
	_, err = Read(t.Context(), Prepared{snapshot, fingerprint}, "7", genesis, func(record Record) error { retained = append(retained, record); return nil })
	if err != nil || len(retained) != 3 {
		t.Fatal("validator-start snapshot unavailable", err, retained)
	}
	if retained[1].Timer == nil || retained[1].Timer.Timer != "validator_start" || retained[1].Timer.TimeoutSHA256 != ops[0].Timer.TimeoutSHA256 || retained[1].Timer.Height != ops[0].Timer.Height || retained[2].Timer == nil || len(retained[2].Timer.Kinds) != 5 {
		t.Fatal("validator-start snapshot metadata changed", retained)
	}
}
