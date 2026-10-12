package headers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/0xmhha/wbft/chain/epoch"
	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

// Fact contains only network-wide fields, keyed by a canonical index. Full
// numbers are decimal strings, independent of the index's 64-bit domain.
type Fact struct {
	Index         string          `json:"index"`
	Number        string          `json:"number"`
	Hash          string          `json:"hash"`
	ParentHash    string          `json:"parent_hash"`
	Time          string          `json:"time"`
	Coinbase      string          `json:"coinbase"`
	Epoch         string          `json:"epoch"`
	Validators    []string        `json:"validators"`
	RoundZero     string          `json:"round_zero"`
	LastProposer  string          `json:"last_proposer"`
	Policy        string          `json:"policy"`
	PrevRound     int64           `json:"prev_round"`
	PrevPrepared  []int64         `json:"prev_prepared"`
	PrevCommitted []int64         `json:"prev_committed"`
	EpochInfo     json.RawMessage `json:"epoch_info"`
	EpochCheck    string          `json:"epoch_check"`
	EpochDetail   string          `json:"epoch_detail"`
}

// Copy preserves seals which the block hash excludes. They are scoped to the
// dataset and node, never used as network-wide consensus participation.
type Copy struct {
	Index     string  `json:"index"`
	Hash      string  `json:"hash"`
	Node      string  `json:"node"`
	Round     int64   `json:"round"`
	Prepared  []int64 `json:"prepared"`
	Committed []int64 `json:"committed"`
	Source    string  `json:"source"`
}

func indices(s *types.AggregatedSeal) []int64 {
	out := []int64{}
	if s != nil {
		for _, v := range s.Sealers.Sealers() {
			out = append(out, int64(v))
		}
	}
	return out
}
func contains(xs []int64, n int64) bool {
	for _, x := range xs {
		if n == x {
			return true
		}
	}
	return false
}

func Analyze(src *Source, cfg *types.Config, index uint64, node string) (Fact, Copy, error) {
	h, err := src.Read(index)
	if err != nil {
		return Fact{}, Copy{}, err
	}
	x, err := codec.DecodeExtra(h)
	if err != nil {
		return Fact{}, Copy{}, err
	}
	env := &header.Env{Config: cfg, Chain: src}
	v, vp, err := header.ValidatorsForVerifying(env, h, nil)
	if err != nil {
		return Fact{}, Copy{}, err
	}
	if v.Len() == 0 {
		return Fact{}, Copy{}, fmt.Errorf("empty validator set")
	}
	for _, s := range []*types.AggregatedSeal{x.PreparedSeal, x.CommittedSeal} {
		for _, i := range indices(s) {
			if i >= int64(v.Len()) {
				return Fact{}, Copy{}, fmt.Errorf("own seal outside validator set")
			}
		}
	}
	for _, s := range []*types.AggregatedSeal{x.PrevPreparedSeal, x.PrevCommittedSeal} {
		for _, i := range indices(s) {
			if i >= int64(vp.Len()) {
				return Fact{}, Copy{}, fmt.Errorf("previous seal outside validator set")
			}
		}
	}
	governing, _, err := validator.GoverningEpochInfo(src, cfg, h, nil)
	if err != nil {
		return Fact{}, Copy{}, err
	}
	f := Fact{Index: strconv.FormatUint(index, 10), Number: h.Number.String(), Hash: codec.BlockHash(h).Hex(), ParentHash: h.ParentHash.Hex(), Time: strconv.FormatUint(h.Time, 10), Coinbase: h.Coinbase.Hex(), Epoch: governing.String(), Validators: []string{}, PrevRound: int64(x.PrevRound), PrevPrepared: indices(x.PrevPreparedSeal), PrevCommitted: indices(x.PrevCommittedSeal), EpochCheck: "not_epoch", EpochInfo: json.RawMessage("null")}
	var last types.Address
	if index > 0 {
		p, err := src.Read(index - 1)
		if err != nil {
			return Fact{}, Copy{}, err
		}
		if codec.BlockHash(p) != h.ParentHash {
			return Fact{}, Copy{}, fmt.Errorf("header does not extend its source parent")
		}

		last = types.ProposerOf(p)
	}
	for _, a := range v.Addresses() {
		f.Validators = append(f.Validators, a.Hex())
	}
	f.RoundZero = v.At(v.CalcProposer(last, 0)).Addr.Hex()
	f.LastProposer = last.Hex()
	f.Policy = strconv.FormatUint(cfg.ConfigAt(h.Number).ProposerPolicy.ID, 10)
	if x.EpochInfo != nil {
		f.EpochInfo, _ = json.Marshal(x.EpochInfo)
		candidates := make([]types.CandidateEntry, len(x.EpochInfo.Candidates))
		for i, c := range x.EpochInfo.Candidates {
			candidates[i].Addr = c.Addr
		}
		for i, idx := range x.EpochInfo.Validators {
			if int(idx) >= len(candidates) || i >= len(x.EpochInfo.BLSPublicKeys) {
				return Fact{}, Copy{}, fmt.Errorf("invalid epoch validator key mapping")
			}
			candidates[idx].BLSPublicKey = x.EpochInfo.BLSPublicKeys[i]
		}
		computed, err := epoch.ComputeNextEpochInfo(src, cfg, h, candidates)
		f.EpochCheck = "matched_header_inputs"
		f.EpochDetail = "Candidate order and selected BLS keys reconstructed from the header; execution state keys are unavailable."
		if err != nil {
			f.EpochCheck = "input_error"
			f.EpochDetail = err.Error()
		} else {
			raw, _ := json.Marshal(computed)
			if !bytes.Equal(raw, f.EpochInfo) {
				f.EpochCheck = "mismatch"
				f.EpochDetail = "Recomputed epoch differs with header-reconstructed candidate keys."
			}
		}
	}
	if src.Err != nil {
		return Fact{}, Copy{}, src.Err
	}
	c := Copy{Index: f.Index, Hash: f.Hash, Node: node, Round: int64(x.Round), Prepared: indices(x.PreparedSeal), Committed: indices(x.CommittedSeal), Source: "rpc"}
	if src.Blocks != "" {
		c.Source = "rlp"
	}
	return f, c, nil
}

// Participation is derived from the child of a header. A missing child is
// unknown, rather than a zero participation row. Own and late seals are per node.
type Participation struct {
	Address       string `json:"address"`
	Prepared      *bool  `json:"prepared"`
	Committed     *bool  `json:"committed"`
	OwnPrepared   *bool  `json:"own_prepared"`
	OwnCommitted  *bool  `json:"own_committed"`
	LatePrepared  *bool  `json:"late_prepared"`
	LateCommitted *bool  `json:"late_committed"`
}
type Row struct {
	ProofHash        *string         `json:"proof_hash"`
	Fact             Fact            `json:"fact"`
	DecisionRound    *int64          `json:"decision_round"`
	RoundSource      string          `json:"round_source"`
	ExpectedProposer *string         `json:"expected_proposer"`
	ProposerDiffers  *bool           `json:"proposer_differs"`
	Cells            []Participation `json:"cells"`
	Copy             *Copy           `json:"copy"`
	Missed           []Opportunity   `json:"missed"`
}
type Opportunity struct {
	Address string `json:"address"`
	Count   int64  `json:"count"`
}

func Derive(f Fact, child *Fact, c *Copy, policy *types.ProposerPolicy, last types.Address) (Row, error) {
	r := Row{Fact: f, Cells: []Participation{}, Copy: c, RoundSource: "unknown", Missed: []Opportunity{}}
	if len(f.Validators) == 0 {
		return r, fmt.Errorf("empty validator set")
	}
	if f.Number == "0" {
		r.RoundSource = "genesis"
	} else if child != nil {
		if child.ParentHash != f.Hash {
			return r, fmt.Errorf("child does not extend the header")
		}
		hash := child.Hash
		r.ProofHash = &hash
		v := child.PrevRound
		r.DecisionRound = &v
		r.RoundSource = "child_prev_round"
	} else if c != nil {
		v := c.Round
		r.DecisionRound = &v
		r.RoundSource = "node_copy"
	}
	if r.DecisionRound != nil && policy != nil {
		addresses := make([]types.Address, len(f.Validators))
		for i, a := range f.Validators {
			addresses[i] = types.Address{}
			if err := addresses[i].UnmarshalText([]byte(a)); err != nil {
				return r, err
			}
		}
		v, err := validator.NewSet(addresses, make([][]byte, len(addresses)), *policy)
		if err != nil {
			return r, err
		}
		a := v.At(v.CalcProposer(last, uint64(*r.DecisionRound))).Addr.Hex()
		r.ExpectedProposer = &a
		diff := a != f.Coinbase
		r.ProposerDiffers = &diff
		count := *r.DecisionRound
		size := int64(v.Len())
		for j := int64(0); j < size && j < count; j++ {
			addr := v.At(v.CalcProposer(last, uint64(j))).Addr.Hex()
			r.Missed = append(r.Missed, Opportunity{Address: addr, Count: (count-1-j)/size + 1})
		}
	}
	for i, a := range f.Validators {
		cell := Participation{Address: a}
		if child != nil && f.Number != "0" {
			p, q := contains(child.PrevPrepared, int64(i)), contains(child.PrevCommitted, int64(i))
			cell.Prepared = &p
			cell.Committed = &q
		}
		if c != nil && f.Number != "0" {
			p, q := contains(c.Prepared, int64(i)), contains(c.Committed, int64(i))
			cell.OwnPrepared = &p
			cell.OwnCommitted = &q
			if cell.Prepared != nil {
				lp, lq := *cell.Prepared && !p, *cell.Committed && !q
				cell.LatePrepared = &lp
				cell.LateCommitted = &lq
			}
		}
		r.Cells = append(r.Cells, cell)
	}
	return r, nil
}
