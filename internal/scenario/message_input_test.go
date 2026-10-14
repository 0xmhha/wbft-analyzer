package scenario

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
)

func TestMessageSnapshotsPinCompleteOriginalScope(t *testing.T) {
	nodes, links := completeFixture()
	delay := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, delay, delay, sim.Stop{Height: 3, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	res, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	inputs := []MessageInput{}
	for i, v := range sc.Validators {
		input := messages.Input{ID: string(rune('a' + i)), Kind: "journal", Node: v.Address().Hex(), Path: filepath.Join(dir, hex.EncodeToString(v.Address().Bytes()))}
		summary, err := messages.Fingerprint(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		result, err := InspectMessageSnapshot(context.Background(), messages.Prepared{Input: input, Summary: summary}, "8282", codec.BlockHash(res.Chain[0].Header).Hex())
		if err != nil || len(result.Records) == 0 {
			t.Fatalf("snapshot %v", err)
		}
		inputs = append(inputs, result)
		summary.SHA256 = strings.Repeat("a", 64)
		if _, err := InspectMessageSnapshot(context.Background(), messages.Prepared{Input: input, Summary: summary}, "8282", codec.BlockHash(res.Chain[0].Header).Hex()); err == nil {
			t.Fatal("wrong snapshot digest accepted")
		}
	}
	ps, err := PairMessageInputs(inputs, pairs.Clock{Model: "shared-host"})
	if err != nil || len(ps) == 0 {
		t.Fatalf("pairs %v", err)
	}
	inputs[0].Records[0].Input = "different"
	if _, err := PairMessageInputs(inputs, pairs.Clock{Model: "shared-host"}); err == nil {
		t.Fatal("source records rebound to another input")
	}
}
