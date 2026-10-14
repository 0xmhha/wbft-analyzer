package scenario

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

type CutOutgoing struct {
	Kind   string `json:"kind"`
	Node   int    `json:"node"`
	FromNS int64  `json:"from_ns"`
	ToNS   int64  `json:"to_ns"`
}

// ApplyCutOutgoing changes only links leaving the selected simulated node.
// The node index is the fitted recorded validator index, never a private key.
func ApplyCutOutgoing(sc sim.Scenario, change CutOutgoing) (sim.Scenario, string, error) {
	if change.Kind != "cut_outgoing" || change.Node < 0 || change.Node >= len(sc.Validators) || change.FromNS < 0 || change.ToNS <= change.FromNS || time.Duration(change.ToNS) > sc.Until.Duration {
		return sc, "", errors.New("invalid outgoing link change")
	}
	from := sc.Validators[change.Node].Address()
	cut := [][2]types.Address{}
	for i, v := range sc.Validators {
		if i != change.Node {
			cut = append(cut, [2]types.Address{from, v.Address()})
		}
	}
	sc.Partitions = append(append([]sim.Partition(nil), sc.Partitions...), sim.Partition{From: time.Duration(change.FromNS), To: time.Duration(change.ToNS), DirectedCut: cut})
	raw, err := json.Marshal(change)
	if err != nil {
		return sc, "", err
	}
	sum := sha256.Sum256(raw)
	return sc, hex.EncodeToString(sum[:]), nil
}

func (c CutOutgoing) Canonical() ([]byte, string, error) {
	if c.Kind != "cut_outgoing" || c.Node < 0 || c.Node >= 256 || c.FromNS < 0 || c.ToNS <= c.FromNS || c.ToNS > int64(24*time.Hour) {
		return nil, "", errors.New("invalid bounded network change")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}
