package headers

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

func TestPublicBlocks(t *testing.T) {
	config, err := os.ReadFile("testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := types.ParseChainConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	src := &Source{Context: context.Background(), Blocks: "testdata"}
	if err := src.Prefetch(0, 4); err != nil {
		t.Fatal(err)
	}
	genesis, copy, err := Analyze(src, cfg, 0, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if genesis.Hash != "0x2bdf79b3d3cc49f9e6638ff81f3bb85065c79945a8fe4556cd0ff47bbfc02490" || genesis.EpochCheck != "matched_header_inputs" || copy.Source != "rlp" {
		t.Fatal(genesis, copy)
	}
	f, c, err := Analyze(src, cfg, 2, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := Analyze(src, cfg, 3, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	row, err := Derive(f, &child, &c, cfg.ConfigAt(types.HeightFromUint64(2)).ProposerPolicy, types.ProposerOf(src.HeaderByNumber(1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(row.Cells) != 7 || row.RoundSource != "child_prev_round" || *row.DecisionRound != child.PrevRound {
		t.Fatal(row)
	}
	// Own round and seals are not canonical facts; changing them leaves the
	// hash and network fact byte-identical, while changing the node's copy.
	h := src.cache[2].Copy()
	x, err := codec.DecodeExtra(h)
	if err != nil {
		t.Fatal(err)
	}
	x.Round += 2
	x.PreparedSeal = nil
	x.CommittedSeal = nil
	h.Extra, err = codec.EncodeExtra(x)
	if err != nil {
		t.Fatal(err)
	}
	src.remember(2, h)
	other, otherCopy, err := Analyze(src, cfg, 2, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(f)
	b, _ := json.Marshal(other)
	if string(a) != string(b) || otherCopy.Round != c.Round+2 {
		t.Fatalf("canonical fact changed: %s / %s", a, b)
	}
}
func TestParticipationAndProposer(t *testing.T) {
	addresses := []string{"0x0000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000002"}
	f := Fact{Index: "18446744073709551615", Number: "18446744073709551616", Hash: "hash", Validators: addresses, Coinbase: addresses[1]}
	child := Fact{Hash: "child-hash", ParentHash: "hash", PrevRound: 3, PrevPrepared: []int64{0, 1}, PrevCommitted: []int64{1}}
	c := Copy{Round: 0, Prepared: []int64{0}, Committed: []int64{}}
	row, err := Derive(f, &child, &c, &types.ProposerPolicy{}, types.Address{})
	if err != nil {
		t.Fatal(err)
	}
	if row.ProofHash == nil || *row.ProofHash != "child-hash" || *row.DecisionRound != 3 || *row.ExpectedProposer != addresses[1] || *row.ProposerDiffers || !*row.Cells[1].LateCommitted || !*row.Cells[1].LatePrepared || *row.Cells[0].LatePrepared {
		t.Fatal(row)
	}
	if row.Missed[0].Count != 2 || row.Missed[1].Count != 1 {
		t.Fatal(row.Missed)
	}
	unknown, err := Derive(f, nil, nil, &types.ProposerPolicy{}, types.Address{})
	if err != nil {
		t.Fatal(err)
	}
	if unknown.DecisionRound != nil || unknown.Cells[0].Prepared != nil || unknown.Cells[0].OwnCommitted != nil {
		t.Fatal("missing proof became zero")
	}
	fallback, err := Derive(f, nil, &c, &types.ProposerPolicy{}, types.Address{})
	if err != nil {
		t.Fatal(err)
	}
	if fallback.RoundSource != "unknown" || fallback.DecisionRound != nil || fallback.ExpectedProposer != nil || fallback.ProposerDiffers != nil || len(fallback.Missed) != 0 || fallback.Cells[0].Prepared != nil || fallback.Copy != &c {
		t.Fatal(fallback)
	}
	child.ParentHash = "wrong"
	if _, err := Derive(f, &child, &c, nil, types.Address{}); err == nil {
		t.Fatal("forked child used as proof")
	}
}
func TestBoundedCache(t *testing.T) {
	s := &Source{CacheLimit: 1000}
	for i := uint64(0); i < 1200; i++ {
		s.remember(i, &types.Header{Number: types.HeightFromUint64(i)})
	}
	if len(s.cache) != 1000 || s.cache[0] != nil || s.cache[1199] == nil {
		t.Fatal(len(s.cache))
	}
}
