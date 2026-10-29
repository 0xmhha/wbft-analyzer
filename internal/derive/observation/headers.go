// Package observation compares captured RPC claims with independent canonical
// header metadata. Structural bindings do not verify aggregate signatures and
// never establish event completeness or message delivery.
package observation

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/observe/participation"
	native "github.com/0xmhha/wbft/rpc"
	"github.com/0xmhha/wbft/types"
)

const Version = "wbft-observation-headers/2"

type Check struct {
	Field    string          `json:"field"`
	Status   string          `json:"status"`
	Required bool            `json:"required"`
	Recorded json.RawMessage `json:"recorded"`
	Expected json.RawMessage `json:"expected"`
}
type Proof struct {
	Index        string   `json:"index"`
	Number       string   `json:"number"`
	Hash         string   `json:"hash"`
	ParentHash   string   `json:"parent_hash"`
	Epoch        string   `json:"epoch"`
	Validators   []string `json:"validators"`
	Policy       string   `json:"policy"`
	LastProposer string   `json:"last_proposer"`
	ChildIndex   string   `json:"child_index"`
	ChildHash    string   `json:"child_hash"`
	NetworkRound *int64   `json:"network_round"`
}
type Binding struct {
	Kind          string        `json:"kind"`
	Height        string        `json:"height"`
	Hash          string        `json:"hash"`
	Status        string        `json:"status"`
	CallOrdinal   int64         `json:"call_ordinal"`
	SourceOrdinal int64         `json:"source_ordinal"`
	Proof         *Proof        `json:"proof"`
	OwnRound      *int64        `json:"own_round"`
	Checks        []Check       `json:"checks"`
	Copy          *headers.Copy `json:"copy"`
}
type Totals struct {
	Validator         string `json:"validator"`
	Heights           int64  `json:"heights"`
	ProposerRounds    int64  `json:"proposer_rounds"`
	Proposed          int64  `json:"proposed"`
	MissedRounds      int64  `json:"missed_rounds"`
	PreviousPrepared  int64  `json:"previous_prepared"`
	PreviousCommitted int64  `json:"previous_committed"`
}
type Summary struct {
	Status      string   `json:"status"`
	Requested   int64    `json:"requested"`
	Covered     int64    `json:"covered"`
	Validators  []Totals `json:"validators"`
	Checks      []Check  `json:"checks"`
	Definitions []string `json:"definitions"`
}
type Result struct {
	Rows    []Binding `json:"rows"`
	Summary Summary   `json:"summary"`
}

func check(field, status string, required bool, recorded, expected any) Check {
	r, _ := json.Marshal(recorded)
	e, _ := json.Marshal(expected)
	return Check{field, status, required, r, e}
}
func equal(field string, required bool, a, b any) Check {
	r, _ := json.Marshal(a)
	e, _ := json.Marshal(b)
	status := "matched"
	if string(r) != string(e) {
		status = "different"
	}
	return Check{field, status, required, r, e}
}
func finish(b *Binding) {
	b.Status = "matched"
	for _, c := range b.Checks {
		if c.Status == "different" {
			b.Status = "different"
			return
		}
		if c.Required && c.Status == "unknown" {
			b.Status = "unknown"
		}
	}
}
func canon(a string) string { return strings.ToLower(a) }
func indices(xs *[]uint32, size int) ([]int64, bool) {
	out := []int64{}
	seen := map[uint32]bool{}
	if xs == nil {
		return out, true
	}
	for _, i := range *xs {
		if int64(i) >= int64(size) || seen[i] {
			return out, false
		}
		seen[i] = true
		out = append(out, int64(i))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, true
}
func has(xs []int64, i int) bool {
	for _, v := range xs {
		if v == int64(i) {
			return true
		}
	}
	return false
}
func validIndices(xs []int64, n int) bool {
	seen := map[int64]bool{}
	for _, i := range xs {
		if i < 0 || i >= int64(n) || seen[i] {
			return false
		}
		seen[i] = true
	}
	return true
}

type context struct {
	fact     headers.Fact
	child    *headers.Fact
	parentOK bool
	childOK  bool
	set      *validator.Set
	last     types.Address
	checks   []Check
}

func resolve(number, hash string, byNumber map[string][]headers.Fact, byIndex map[string]headers.Fact) (*context, *Proof, []Check) {
	fs := byNumber[number]
	if len(fs) == 0 {
		return nil, nil, []Check{check("canonical_full_number", "unknown", true, number, nil)}
	}
	if len(fs) > 1 {
		return nil, nil, []Check{check("canonical_full_number_unique", "different", true, number, len(fs))}
	}
	f := fs[0]
	p := &Proof{Index: f.Index, Number: f.Number, Hash: f.Hash, ParentHash: f.ParentHash, Epoch: f.Epoch, Validators: f.Validators, Policy: f.Policy, LastProposer: f.LastProposer}
	ctx := &context{fact: f, checks: []Check{equal("block_hash", true, hash, f.Hash)}}
	index, e := strconv.ParseUint(f.Index, 10, 64)
	if e != nil {
		ctx.checks = append(ctx.checks, check("canonical_index", "different", true, f.Index, "uint64"))
		return ctx, p, ctx.checks
	}
	if index == 0 {
		ctx.parentOK = true
	} else if parent, ok := byIndex[strconv.FormatUint(index-1, 10)]; ok {
		c := equal("canonical_parent", true, f.ParentHash, parent.Hash)
		ctx.checks = append(ctx.checks, c)
		ctx.parentOK = c.Status == "matched"
	} else {
		ctx.checks = append(ctx.checks, check("canonical_parent", "unknown", true, f.ParentHash, nil))
	}
	if index != ^uint64(0) {
		if child, ok := byIndex[strconv.FormatUint(index+1, 10)]; ok {
			ctx.child = &child
			p.ChildHash, p.ChildIndex = child.Hash, child.Index
			c := equal("canonical_child_parent", true, child.ParentHash, f.Hash)
			ctx.checks = append(ctx.checks, c)
			ctx.childOK = c.Status == "matched" && validIndices(child.PrevPrepared, len(f.Validators)) && validIndices(child.PrevCommitted, len(f.Validators)) && child.PrevRound >= 0 && uint64(child.PrevRound) <= uint64(^uint32(0))
			if ctx.childOK {
				v := child.PrevRound
				p.NetworkRound = &v
			} else {
				ctx.checks = append(ctx.checks, check("canonical_child_seals", "different", true, child.PrevRound, "valid parent validator indices and round"))
			}
		}
	}
	policy, pe := strconv.ParseUint(f.Policy, 10, 64)
	if policy > types.Sticky {
		pe = fmt.Errorf("unsupported canonical proposer policy")
	}
	addresses := []types.Address{}
	seen := map[string]bool{}
	for _, a := range f.Validators {
		var addr types.Address
		if e = addr.UnmarshalText([]byte(a)); e != nil || seen[canon(a)] {
			pe = fmt.Errorf("invalid canonical validators")
		}
		seen[canon(a)] = true
		addresses = append(addresses, addr)
	}
	if e = ctx.last.UnmarshalText([]byte(f.LastProposer)); e != nil {
		pe = e
	}
	if pe == nil && len(addresses) > 0 {
		ctx.set, pe = validator.NewSet(addresses, make([][]byte, len(addresses)), types.ProposerPolicy{ID: policy})
		if pe == nil {
			for i, a := range f.Validators {
				if canon(a) != canon(ctx.set.At(i).Addr.Hex()) {
					pe = fmt.Errorf("canonical validator ordering mismatch")
					break
				}
			}
		}
	}
	if pe != nil || ctx.set == nil {
		ctx.set = nil
		ctx.checks = append(ctx.checks, check("canonical_validator_policy", "different", true, f.Policy, "valid ordered validator set"))
	}
	return ctx, p, ctx.checks
}

// Build never derives identity from low64 heights or arrival timestamps. Every
// source row remains visible, including missing/forked headers and gaps.
func Build(facts []headers.Fact, calls []observe.Call, node string) (Result, error) {
	out := Result{Rows: []Binding{}, Summary: Summary{Status: "unavailable", Validators: []Totals{}, Checks: []Check{}, Definitions: []string{"Own copy and RPC record rounds are node-local; differences from the successor previous round do not invalidate bindings.",
		"Canonical proposer opportunities include rounds through the child-proved decision only; RPC totals also count higher node-entered rounds.", "Previous seal inclusion is network metadata; own seal inclusion and late flags are node-copy claims. Aggregate signatures are not checked by this projection.", "Delay and evidence counters require local observations and cannot be independently derived from headers."}}}
	if len(facts) > 6144 || len(calls) > observe.MaxCalls {
		return out, fmt.Errorf("observation header projection exceeds source limits")
	}
	// Bound output before allocating per-validator comparison rows. Stored source
	// invariants are checked again here so a damaged capture cannot evade limits.
	estimated := 0
	for _, c := range calls {
		switch c.Method {
		case "wbft_nodeInfo":
			if c.Status == "available" {
				estimated++
			}
		case "wbft_headerCopy":
			estimated++
		case "wbft_participation":
			if c.Status == "available" {
				var rs []participation.Record
				if e := json.Unmarshal(c.Data, &rs); e != nil {
					return out, e
				}
				if len(rs) > 1024 {
					return out, fmt.Errorf("participation scope exceeds limit")
				}
				estimated += len(rs)
			}
		}
	}
	if estimated > 4096 {
		return out, fmt.Errorf("binding output exceeds row limit")
	}
	byNumber := map[string][]headers.Fact{}
	byIndex := map[string]headers.Fact{}
	for _, f := range facts {
		if _, ok := byIndex[f.Index]; ok {
			return out, fmt.Errorf("duplicate canonical index")
		}
		byIndex[f.Index] = f
		byNumber[f.Number] = append(byNumber[f.Number], f)
	}
	for _, c := range calls {
		if c.Method != "wbft_nodeInfo" || c.Status != "available" {
			continue
		}
		var n native.NodeInfo
		if e := json.Unmarshal(c.Data, &n); e != nil {
			return out, e
		}
		_, proof, checks := resolve(n.Head.Number, n.Head.Hash.String(), byNumber, byIndex)
		b := Binding{Kind: "head", Height: n.Head.Number, Hash: n.Head.Hash.String(), CallOrdinal: c.Ordinal, Proof: proof, Checks: checks}
		finish(&b)
		out.Rows = append(out.Rows, b)
	}
	copies := map[string][]*Binding{}
	copyClaims := map[string]observe.Copy{}
	for _, c := range calls {
		if c.Method != "wbft_headerCopy" {
			continue
		}
		b := Binding{Kind: "copy", Status: "unknown", CallOrdinal: c.Ordinal, Checks: []Check{}}
		if c.Status != "available" {
			b.Checks = append(b.Checks, check("rpc_copy_available", "unknown", true, c.Status, nil))
			out.Rows = append(out.Rows, b)
			continue
		}
		var cp observe.Copy
		if e := json.Unmarshal(c.Data, &cp); e != nil {
			return out, e
		}
		b.Height, b.Hash = cp.Number, cp.Hash
		own := int64(cp.Round)
		b.OwnRound = &own
		ctx, p, checks := resolve(cp.Number, cp.Hash, byNumber, byIndex)
		b.Proof, b.Checks = p, checks
		if ctx != nil {
			prepared, pok := indices(cp.Prepared, len(ctx.fact.Validators))
			committed, cok := indices(cp.Committed, len(ctx.fact.Validators))
			status := "matched"
			if !pok || !cok {
				status = "unknown"
				if cp.Prepared != nil && !pok || cp.Committed != nil && !cok {
					status = "different"
				}
			}
			b.Checks = append(b.Checks, check("own_seal_indices", status, true, []any{cp.Prepared, cp.Committed}, "null seals or unique indices within the canonical validator set"))
			// The node's round is independent of the successor's hash-bound round.
			if !ctx.childOK {
				b.Checks = append(b.Checks, check("network_decision_round", "unknown", false, own, nil))
			}
			finish(&b)
			if b.Status == "matched" {
				cpMeta := headers.Copy{Index: ctx.fact.Index, Hash: cp.Hash, Node: node, Round: own, Prepared: prepared, Committed: committed, Source: "rpc_observation_structural"}
				b.Copy = &cpMeta
			}
		} else {
			finish(&b)
		}
		out.Rows = append(out.Rows, b)
	}
	// Pointers are established after append so slice growth cannot detach them.
	for i := range out.Rows {
		b := &out.Rows[i]
		if b.Kind == "copy" && b.Height != "" {
			copies[b.Height] = append(copies[b.Height], b)
		}
	}
	for _, c := range calls {
		if c.Method == "wbft_headerCopy" && c.Status == "available" {
			var cp observe.Copy
			_ = json.Unmarshal(c.Data, &cp)
			if len(copies[cp.Number]) == 1 {
				copyClaims[cp.Number] = cp
			}
		}
	}
	totals := map[string]*Totals{}
	get := func(a string) *Totals {
		a = canon(a)
		if totals[a] == nil {
			totals[a] = &Totals{Validator: a}
		}
		return totals[a]
	}
	records := []participation.Record{}
	for _, c := range calls {
		if c.Method != "wbft_participation" {
			continue
		}
		if c.Status != "available" {
			out.Summary.Checks = append(out.Summary.Checks, check("participation_available", "unknown", true, c.Status, nil))
			continue
		}
		if e := json.Unmarshal(c.Data, &records); e != nil {
			return out, e
		}
		out.Summary.Requested = int64(len(records))
		for i, r := range records {
			b := Binding{Kind: "participation", Height: r.Height, Hash: r.Hash, CallOrdinal: c.Ordinal, SourceOrdinal: int64(i + 1), Status: "unknown", Checks: []Check{}}
			if r.Gap {
				b.Checks = append(b.Checks, check("participation_gap", "unknown", true, true, nil))
				out.Rows = append(out.Rows, b)
				continue
			}
			ctx, p, checks := resolve(r.Height, r.Hash, byNumber, byIndex)
			b.Proof, b.Checks = p, checks
			if ctx == nil {
				finish(&b)
				out.Rows = append(out.Rows, b)
				continue
			}
			b.Checks = append(b.Checks, equal("proposer_coinbase", true, canon(r.Proposer), canon(ctx.fact.Coinbase)))
			if own, err := strconv.ParseUint(r.Round, 10, 32); err == nil {
				round := int64(own)
				b.OwnRound = &round
			}
			if !ctx.childOK {
				b.Checks = append(b.Checks, check("network_decision_round", "unknown", true, r.Round, nil))
			}
			cp, cpKnown := copyClaims[r.Height]
			copyKnown := cpKnown && len(copies[r.Height]) == 1 && copies[r.Height][0].Status == "matched" && cp.Hash == r.Hash
			if copyKnown {
				b.Checks = append(b.Checks, equal("record_round_vs_copy", true, r.Round, strconv.FormatUint(uint64(cp.Round), 10)))
			} else {
				b.Checks = append(b.Checks, check("own_copy_binding", "unknown", true, r.Round, nil))
			}
			committed := map[string]bool{}
			for _, v := range r.Validators {
				prefix := v.Round + ":" + canon(v.Validator) + ":"
				vi := int(v.Index)
				valid := vi < len(ctx.fact.Validators) && canon(ctx.fact.Validators[vi]) == canon(v.Validator)
				status := "matched"
				expected := "canonical validator at the recorded index"
				if !valid {
					status = "different"
				}
				b.Checks = append(b.Checks, check(prefix+"member_index", status, true, []any{v.Validator, v.Index}, expected))
				if !valid {
					continue
				}
				if v.Round == r.Round {
					committed[canon(v.Validator)] = true
				}
				for _, flag := range []struct {
					name     string
					recorded bool
					expected bool
					known    bool
				}{{"inPrevPrepared", v.InPrevPrepared, v.Round == r.Round && ctx.childOK && has(ctx.child.PrevPrepared, vi), ctx.childOK}, {"inPrevCommitted", v.InPrevCommitted, v.Round == r.Round && ctx.childOK && has(ctx.child.PrevCommitted, vi), ctx.childOK}, {"sealedPrepared", v.SealedPrepared, v.Round == r.Round && copyKnown && hasU(cp.Prepared, vi), copyKnown}, {"sealedCommitted", v.SealedCommitted, v.Round == r.Round && copyKnown && hasU(cp.Committed, vi), copyKnown}, {"extra", v.Extra, v.Round == r.Round && ctx.childOK && copyKnown && (has(ctx.child.PrevPrepared, vi) || has(ctx.child.PrevCommitted, vi)) && !hasU(cp.Prepared, vi) && !hasU(cp.Committed, vi), ctx.childOK && copyKnown}} {
					if flag.known {
						b.Checks = append(b.Checks, equal(prefix+flag.name, true, flag.recorded, flag.expected))
					} else {
						b.Checks = append(b.Checks, check(prefix+flag.name, "unknown", true, flag.recorded, nil))
					}
				}
				if ctx.set != nil {
					round, ok := new(big.Int).SetString(v.Round, 10)
					if ok {
						expected := ctx.set.At(ctx.set.CalcProposer(ctx.last, round.Uint64())).Addr.Hex()
						b.Checks = append(b.Checks, equal(prefix+"is_proposer", true, v.IsProposer, canon(v.Validator) == canon(expected)))
					}
				}
			}
			b.Checks = append(b.Checks, equal("committed_validator_coverage", true, len(committed), len(ctx.fact.Validators)))
			if ctx.set != nil {
				for _, rd := range r.Rounds {
					round, ok := new(big.Int).SetString(rd.Round, 10)
					if ok {
						expected := ctx.set.At(ctx.set.CalcProposer(ctx.last, round.Uint64())).Addr.Hex()
						b.Checks = append(b.Checks, equal("round:"+rd.Round+":proposer", true, canon(rd.Proposer), canon(expected)))
					}
				}
			}
			finish(&b)
			out.Rows = append(out.Rows, b)
			// Canonical expectations use all resolvable requested non-gap heights, even
			// when the RPC row differs; excluding disagreements would hide the defect.
			if ctx.parentOK && ctx.childOK && ctx.set != nil {
				out.Summary.Covered++
				for vi, a := range ctx.fact.Validators {
					v := get(a)
					v.Heights++
					if has(ctx.child.PrevPrepared, vi) {
						v.PreviousPrepared++
					}
					if has(ctx.child.PrevCommitted, vi) {
						v.PreviousCommitted++
					}
				}
				get(ctx.fact.Coinbase).Proposed++
				round := ctx.child.PrevRound
				size := int64(ctx.set.Len())
				for j := int64(0); j < size && j <= round; j++ {
					addr := ctx.set.At(ctx.set.CalcProposer(ctx.last, uint64(j))).Addr.Hex()
					get(addr).ProposerRounds += (round-j)/size + 1
					if j < round {
						get(addr).MissedRounds += (round-1-j)/size + 1
					}
				}
			}
		}
	}
	for _, v := range totals {
		out.Summary.Validators = append(out.Summary.Validators, *v)
	}
	sort.Slice(out.Summary.Validators, func(i, j int) bool { return out.Summary.Validators[i].Validator < out.Summary.Validators[j].Validator })
	if len(records) > 0 {
		nongap := int64(0)
		for _, r := range records {
			if !r.Gap {
				nongap++
			}
		}
		out.Summary.Status = "partial"
		if out.Summary.Covered == nongap {
			out.Summary.Status = "complete_comparison"
			reported := participation.Summarize(records)
			by := map[string]participation.ValidatorSummary{}
			for _, v := range reported.Validators {
				by[canon(v.Validator)] = v
			}
			for _, v := range out.Summary.Validators {
				r := by[v.Validator]
				for _, field := range []struct {
					name string
					a, b int64
				}{{"heights", int64(r.Heights), v.Heights}, {"proposer_rounds", int64(r.ProposerRounds), v.ProposerRounds}, {"proposed", int64(r.Proposed), v.Proposed}, {"missed_rounds", int64(r.Missed), v.MissedRounds}, {"previous_committed", int64(r.Sealed), v.PreviousCommitted}} {
					out.Summary.Checks = append(out.Summary.Checks, equal(v.Validator+":"+field.name, false, field.a, field.b))
				}
			}
		}
	}
	sort.SliceStable(out.Rows, func(i, j int) bool {
		a, b := out.Rows[i], out.Rows[j]
		if a.CallOrdinal != b.CallOrdinal {
			return a.CallOrdinal < b.CallOrdinal
		}
		return a.SourceOrdinal < b.SourceOrdinal
	})
	if len(out.Rows) > 4096 {
		return out, fmt.Errorf("observation header projection exceeds row limit")
	}
	return out, nil
}
func hasU(xs *[]uint32, i int) bool {
	if xs == nil {
		return false
	}
	for _, v := range *xs {
		if int64(v) == int64(i) {
			return true
		}
	}
	return false
}
