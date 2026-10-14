package messages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestTimerOperationProjectionPreservesExactMetadataWithoutInputBytes(t *testing.T) {
	dir := t.TempDir()
	node := types.Address{19: 1}
	writer, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Self: node, Run: "synthetic-timers", ChainID: big.NewInt(7), Core: journal.CoreOptions{TimerTrace: 1}})
	if err != nil {
		t.Fatal(err)
	}
	input, err := inputlog.Encode(consensus.Timeout{Kind: consensus.RetryTimer, Gen: 9007199254740993, View: types.View{Sequence: types.HeightFromUint64(9007199254740994), Round: types.RoundFromUint64(3)}})
	if err != nil {
		t.Fatal(err)
	}
	writer.Put(journal.Record{Body: &journal.TimerRec{Sequence: 9007199254740993, EngineRun: 2, Step: 7, Output: 3, ArmEngineRun: 2, ArmStep: 7, ArmOutput: 3, Source: "core", Action: "queued", Mono: 20, WallNs: 1577836800000000020, EntryMono: 0, Deadline: 10, Input: input}})
	writer.Put(journal.Record{Body: &journal.TimerRec{Sequence: 9007199254740994, EngineRun: 2, Step: 8, Output: 2, Source: "core", Action: "cancel", Mono: 21, WallNs: 1577836800000000021, Kinds: []uint64{0, 1, 2}}})
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
	if len(ops) != 2 || ops[0].Timer == nil || ops[0].Timer.Sequence != "9007199254740993" || ops[0].Timer.Generation != "9007199254740993" || ops[0].Timer.Height != "9007199254740994" || ops[0].Timer.TimeoutSHA256 != hex.EncodeToString(sum[:]) || ops[0].Timer.EntryMono != "0" || ops[0].Mono == nil || *ops[0].Mono != "20" || ops[0].Timer.Decode != "complete" {
		t.Fatal("precise evidence lost", ops)
	}
	if len(ops[1].Timer.Kinds) != 3 || ops[1].Timer.Decode != "not_applicable" {
		t.Fatal("cancel evidence lost", ops[1])
	}
	encoded, err := json.Marshal(ops)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "payload") || strings.Contains(string(encoded), "signature") || strings.Contains(string(encoded), "\"Input\"") {
		t.Fatal("input material crossed projection boundary", string(encoded))
	}
}
