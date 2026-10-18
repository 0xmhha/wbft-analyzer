package statewitness

import (
	"testing"

	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/types"
	"github.com/ethereum/go-ethereum/common"
)

func TestEpochKeysRemainSeparateFromSelectionAndDiligence(t *testing.T) {
	state, err := DecodeValidatorState(validatorExample(t))
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	seed[31] = 1
	secret, err := bls.DeriveSecretKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.EpochInfo{Candidates: []types.Candidate{{Addr: common.HexToAddress("0x01")}, {Addr: common.HexToAddress("0x02")}}, Validators: []uint32{0}, BLSPublicKeys: [][]byte{secret.PublicKey().Bytes()}}
	if got := epochEvidence(info, state); got.Keys != "matched" {
		t.Fatal(got)
	}
	before := EpochDigest(info)
	info.Candidates[0].Diligence = 7
	if EpochDigest(info) == before || epochEvidence(info, state).Keys != "matched" {
		t.Fatal("key comparison silently became a diligence verdict")
	}
	if epochEvidence(nil, state).Keys != "not_epoch" {
		t.Fatal("absent epoch became a positive key comparison")
	}
	for name, mutate := range map[string]func(*types.EpochInfo){
		"candidate order":  func(e *types.EpochInfo) { e.Candidates[0], e.Candidates[1] = e.Candidates[1], e.Candidates[0] },
		"wrong key":        func(e *types.EpochInfo) { e.BLSPublicKeys[0] = make([]byte, 48) },
		"keyless selected": func(e *types.EpochInfo) { e.Validators[0] = 1 },
		"invalid index":    func(e *types.EpochInfo) { e.Validators[0] = 2 },
		"duplicate selection": func(e *types.EpochInfo) {
			e.Validators = []uint32{0, 0}
			e.BLSPublicKeys = append(e.BLSPublicKeys, e.BLSPublicKeys[0])
		},
		"missing key": func(e *types.EpochInfo) { e.BLSPublicKeys = nil },
		"empty epoch": func(e *types.EpochInfo) { *e = types.EpochInfo{} },
	} {
		t.Run(name, func(t *testing.T) {
			e := info.Copy()
			mutate(e)
			if epochEvidence(e, state).Keys != "mismatch" {
				t.Fatal("inconsistent epoch key list was accepted")
			}
		})
	}
}
