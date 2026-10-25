package messages

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/chain/window"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func observationSegment(t *testing.T) *journal.SegmentRec {
	t.Helper()
	full := types.MustHeightFromBig(new(big.Int).Lsh(big.NewInt(1), 128))
	o, err := journal.NewObservationOptions(window.Config{ChainID: big.NewInt(7), GenesisHash: types.Hash{1}, Activation: full,
		Window: 2, Codec: wire.Limits{ExtraBytes: 1 << 20, Proofs: 16, SettlementRows: 32, Validators: 32}, StateBytes: 1 << 20,
		CheckpointBytes: 2 << 20, AddressRows: 32}, full, 128, 4)
	if err != nil {
		t.Fatal(err)
	}
	o.Checkpoint = []byte("opaque checkpoint bytes")
	return &journal.SegmentRec{Identity: journal.Identity{Self: types.Address{19: 1}, Run: "observation-metadata",
		ChainID: big.NewInt(7), GenesisHash: o.GenesisHash, Core: journal.CoreOptions{Observation: o}}}
}

func TestObservationJournalRetainsExactPolicyWithoutStateClaim(t *testing.T) {
	segment := observationSegment(t)
	in := Input{ID: "observation-policy", Kind: "journal", Node: self, Path: t.TempDir()}
	writer, err := journal.Open(journal.Options{Dir: in.Path, Synchronous: true}, segment.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	summary, err := Fingerprint(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	var rows []Record
	_, err = Read(t.Context(), Prepared{in, summary}, "7", segment.GenesisHash.Hex(), func(r Record) error { rows = append(rows, r); return nil })
	if err != nil || len(rows) != 1 || rows[0].Type != "segment" || rows[0].Observation == nil {
		t.Fatal("recorded policy unavailable", err, rows)
	}
	o := rows[0].Observation
	full := new(big.Int).Lsh(big.NewInt(1), 128).String()
	if o.Retention != full || o.Activation != full || o.ReplayHeaders != "4" || o.CheckpointStatus != "recorded_requires_chain" || o.Limits["proofs"] != "16" {
		t.Fatal("precision or checkpoint trust scope changed", o)
	}
	raw, err := json.Marshal(rows)
	if err != nil || strings.Contains(string(raw), "opaque checkpoint bytes") {
		t.Fatal("checkpoint payload was projected", err)
	}
}

func TestObservationProjectionRefusesChangedClosedDeclarations(t *testing.T) {
	for _, change := range []func(*journal.SegmentRec){
		func(s *journal.SegmentRec) { s.Core.Observation.Profile++ },
		func(s *journal.SegmentRec) { s.Core.Observation.Retention = "3" },
		func(s *journal.SegmentRec) { s.Core.Observation.PolicyDigest[0] ^= 1 },
		func(s *journal.SegmentRec) { s.GenesisHash[0] ^= 1 },
	} {
		s := observationSegment(t)
		change(s)
		if _, err := projectObservationProfile(s); err == nil {
			t.Fatal("changed closed declaration accepted")
		}
	}
	if got, err := projectObservationProfile(&journal.SegmentRec{}); err != nil || got != nil {
		t.Fatal("legacy metadata acquired an observation profile", err)
	}
}
