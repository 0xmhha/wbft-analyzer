package statewitness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/0xmhha/wbft/types"
)

type EpochEvidence struct {
	SHA256 string `json:"sha256"`
	Keys   string `json:"keys" enum:"not_epoch,matched,mismatch"`
}

// EpochDigest binds the interpreted epoch fields to the decoded source
// header. It does not verify diligence, selection policy or aggregate seals.
func EpochDigest(info *types.EpochInfo) string {
	raw, _ := json.Marshal(info)
	return digest(raw).SHA256
}

func epochEvidence(info *types.EpochInfo, state ValidatorState) EpochEvidence {
	out := EpochEvidence{SHA256: EpochDigest(info), Keys: "not_epoch"}
	if info == nil {
		return out
	}
	out.Keys = "mismatch"
	if len(info.Candidates) == 0 || len(info.Candidates) != len(state.Candidates) || len(info.Validators) == 0 || len(info.Validators) != len(info.BLSPublicKeys) {
		return out
	}
	for i, candidate := range info.Candidates {
		if !strings.EqualFold(candidate.Addr.Hex(), state.Candidates[i].Address) {
			return out
		}
	}
	seen := map[uint32]bool{}
	for i, index := range info.Validators {
		if int(index) >= len(state.Candidates) || seen[index] {
			return out
		}
		seen[index] = true
		key := info.BLSPublicKeys[i]
		sum := sha256.Sum256(key)
		candidate := state.Candidates[index]
		if len(key) != 48 || candidate.KeyBytes != len(key) || candidate.KeySHA256 != hex.EncodeToString(sum[:]) {
			return out
		}
	}
	out.Keys = "matched"
	return out
}
