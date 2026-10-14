package scenario

import (
	"bytes"
	"errors"
	"sort"
	"strconv"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// TestValidators produces only deterministic test keys. Their sorted address
// ranks are mapped to recorded address ranks, while the returned list retains
// the recorded validator order (which need not itself be sorted).
func TestValidators(recorded []types.Address) ([]sim.Validator, error) {
	if len(recorded) < 1 || len(recorded) > 256 {
		return nil, errors.New("invalid validator count")
	}
	indices := make([]int, len(recorded))
	keys := make([]sim.Validator, len(recorded))
	seen := map[types.Address]bool{}
	for i, a := range recorded {
		if a == (types.Address{}) || seen[a] {
			return nil, errors.New("invalid recorded validator")
		}
		seen[a] = true
		indices[i] = i
		v, err := sim.NewValidator(keccak.Sum256Bytes([]byte("wbft-network-scenario-test-key-" + strconv.Itoa(i))))
		if err != nil {
			return nil, err
		}
		keys[i] = v
	}
	sort.Slice(indices, func(i, j int) bool { return bytes.Compare(recorded[indices[i]][:], recorded[indices[j]][:]) < 0 })
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i].Address(), keys[j].Address()
		return bytes.Compare(a[:], b[:]) < 0
	})
	out := make([]sim.Validator, len(keys))
	for rank, index := range indices {
		out[index] = keys[rank]
	}
	return out, nil
}
