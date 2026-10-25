package scenario

import (
	"errors"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/chain/window"
	wire "github.com/0xmhha/wbft/codec/window"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestObservationNodeCannotSilentlyUseLegacyNetworkModel(t *testing.T) {
	address := types.Address{19: 1}
	options, err := journal.NewObservationOptions(window.Config{ChainID: big.NewInt(7), GenesisHash: types.Hash{1}, Activation: types.HeightFromUint64(3),
		Window: 2, Codec: wire.Limits{ExtraBytes: 1 << 20, Proofs: 16, SettlementRows: 32, Validators: 32}, StateBytes: 1 << 20,
		CheckpointBytes: 2 << 20, AddressRows: 32}, types.HeightFromUint64(3), 128, 4)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writer, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Self: address, Run: "observation-declaration",
		ChainID: big.NewInt(7), GenesisHash: options.GenesisHash, Core: journal.CoreOptions{Self: address, Observation: options,
			ChainConfig: []byte(`{"chainId":7,"anzeon":{"wbft":{"epochLength":10}}}`), Profile: "compat", Improvements: uint64(consensus.RestartSafety)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := InspectNodeOptions(t.Context(), dir, address); !errors.Is(err, ErrObservationModelUnavailable) {
		t.Fatal("observation-enabled source was fitted with a legacy model", err)
	}
}
