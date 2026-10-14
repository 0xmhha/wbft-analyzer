package scenario

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/types"
)

func TestSyntheticValidatorRankAndProposerOrder(t *testing.T) {
	recorded := []types.Address{{19: 30}, {19: 10}, {19: 40}, {19: 20}}
	keys, err := TestValidators(recorded)
	if err != nil {
		t.Fatal(err)
	}
	again, err := TestValidators(recorded)
	if err != nil || !reflect.DeepEqual(keys, again) {
		t.Fatal("test key mapping nondeterministic")
	}
	addresses := []types.Address{}
	bls := make([][]byte, len(keys))
	for _, k := range keys {
		addresses = append(addresses, k.Address())
	}
	for i := range recorded {
		for j := range recorded {
			if (bytes.Compare(recorded[i][:], recorded[j][:]) < 0) != (bytes.Compare(addresses[i][:], addresses[j][:]) < 0) {
				t.Fatal("address rank changed")
			}
		}
	}
	for _, policy := range []uint64{0, types.Sticky, 2} {
		a, _ := validator.NewSet(recorded, bls, types.ProposerPolicy{ID: policy})
		b, _ := validator.NewSet(addresses, bls, types.ProposerPolicy{ID: policy})
		for i := range recorded {
			for r := uint64(0); r < 12; r++ {
				if a.CalcProposer(recorded[i], r) != b.CalcProposer(addresses[i], r) {
					t.Fatal("proposer order changed")
				}
			}
		}
	}
	if _, err := TestValidators([]types.Address{{19: 1}, {19: 1}}); err == nil {
		t.Fatal("duplicate address accepted")
	}
}
