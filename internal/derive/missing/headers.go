package missing

import (
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"strconv"
)

type Copy struct {
	DatasetID int64
	Copy      headers.Copy
}

// HeaderProjection binds own copies to the canonical hash and previous seals
// to the actual parent, retaining a missing child as an unknown network round.
func HeaderProjection(facts []headers.Fact, copies []Copy) ([]Height, error) {
	byIndex := map[string]headers.Fact{}
	for _, f := range facts {
		if _, ok := byIndex[f.Index]; ok {
			return nil, fmt.Errorf("duplicate canonical index")
		}
		byIndex[f.Index] = f
	}
	copyIndex := map[string][]Copy{}
	for _, c := range copies {
		copyIndex[c.Copy.Index] = append(copyIndex[c.Copy.Index], c)
	}
	out := make([]Height, 0, len(facts))
	for _, f := range facts {
		h := Height{Index: f.Index, Number: f.Number, Hash: f.Hash, Validators: f.Validators, Seals: []Seal{}}
		index, e := strconv.ParseUint(f.Index, 10, 64)
		if e != nil || index == ^uint64(0) {
			return nil, fmt.Errorf("invalid canonical index")
		}
		if child, ok := byIndex[strconv.FormatUint(index+1, 10)]; ok {
			if child.ParentHash != f.Hash {
				return nil, fmt.Errorf("canonical child does not extend parent")
			}
			h.ChildHash, h.ChildParentHash, h.Round = child.Hash, child.ParentHash, strconv.FormatInt(child.PrevRound, 10)
			for _, p := range []struct {
				phase   string
				indices []int64
			}{{"PREPARE", child.PrevPrepared}, {"COMMIT", child.PrevCommitted}} {
				for _, i := range p.indices {
					if i < 0 || i >= int64(len(f.Validators)) {
						return nil, fmt.Errorf("previous seal outside validator set")
					}
					h.Seals = append(h.Seals, Seal{Validator: f.Validators[i], Phase: p.phase, Index: child.Index, Hash: child.Hash, Round: h.Round, Basis: "previous"})
				}
			}
		}
		for _, c := range copyIndex[f.Index] {
			if c.Copy.Hash != f.Hash {
				return nil, fmt.Errorf("own copy differs from canonical hash")
			}
			for _, p := range []struct {
				phase   string
				indices []int64
			}{{"PREPARE", c.Copy.Prepared}, {"COMMIT", c.Copy.Committed}} {
				for _, i := range p.indices {
					if i < 0 || i >= int64(len(f.Validators)) {
						return nil, fmt.Errorf("own seal outside validator set")
					}
					h.Seals = append(h.Seals, Seal{Validator: f.Validators[i], Phase: p.phase, Index: f.Index, Hash: f.Hash, Round: strconv.FormatInt(c.Copy.Round, 10), Node: c.Copy.Node, DatasetID: c.DatasetID, Basis: "own"})
				}
			}
		}
		out = append(out, h)
	}
	return out, nil
}
