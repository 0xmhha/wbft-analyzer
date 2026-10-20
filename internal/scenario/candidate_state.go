package scenario

import (
	"errors"
	"math"
	"math/big"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

var errCandidateState = errors.New("candidate state schedule cannot represent the requested epoch")

func parentCandidatesAt(params sim.Params, block uint64) (bool, error) {
	raw, configured := params.RuleActivations[types.EpochInfoInProposal]
	if !configured {
		return false, nil
	}
	activation, ok := new(big.Int).SetString(raw, 10)
	if !ok || activation.Sign() < 0 || activation.String() != raw {
		return false, errCandidateState
	}
	return activation.Cmp(new(big.Int).SetUint64(block)) <= 0, nil
}

// candidateInputBlock maps a desired selection epoch to its modeled candidate
// input. The input is exogenous membership, not observed governance execution.
func candidateInputBlock(params sim.Params, block uint64) (uint64, error) {
	if block == 0 {
		return 0, errCandidateState
	}
	if _, configured := params.RuleActivations[types.EpochInfoInProposal]; !configured {
		return block, nil
	}
	if params.EpochLength == 0 || block%params.EpochLength != 0 {
		return 0, errCandidateState
	}
	parent, err := parentCandidatesAt(params, block)
	if err != nil {
		return 0, err
	}
	if parent {
		return block - 1, nil
	}
	return block, nil
}

// candidateSelectionEpoch reports the first epoch affected by an input.
// A request must not silently alter an earlier selection epoch.
func candidateSelectionEpoch(params sim.Params, input uint64) (uint64, error) {
	length := params.EpochLength
	if length == 0 {
		return 0, errCandidateState
	}
	quotient := input / length
	if input%length != 0 {
		quotient++
	}
	if quotient == 0 {
		quotient = 1
	}
	if quotient > math.MaxUint64/length {
		return 0, errCandidateState
	}
	block := quotient * length
	parent, err := parentCandidatesAt(params, block)
	if err != nil {
		return 0, err
	}
	if !parent {
		if input == 0 || input%length != 0 {
			return 0, errCandidateState
		}
		return input, nil
	}
	if input == block {
		if block > math.MaxUint64-length {
			return 0, errCandidateState
		}
		block += length
	}
	return block, nil
}
