package governance

import (
	"encoding/json"
	"math/big"
	"strings"
)

func identity(raw json.RawMessage) (Identity, error) {
	var w struct {
		Impl    string   `json:"impl"`
		Address string   `json:"address"`
		ChainID *big.Int `json:"chainId"`
		Genesis string   `json:"genesisHash"`
		Head    struct {
			Number string `json:"number"`
			Hash   string `json:"hash"`
		} `json:"head"`
	}
	if decode(raw, &w, "impl", "address", "chainId", "genesisHash", "head") != nil || w.Impl != "wbft" || !fixed(w.Address, 20) || w.ChainID == nil || w.ChainID.Sign() < 0 || w.ChainID.BitLen() > 256 || !fixed(w.Genesis, 32) || !fixed(w.Head.Hash, 32) {
		return Identity{}, ErrInvalid
	}
	if len(w.Head.Number) > 156 {
		return Identity{}, ErrInvalid
	}
	n, ok := new(big.Int).SetString(w.Head.Number, 10)
	if !ok || n.Sign() < 0 || n.BitLen() > 512 || n.String() != w.Head.Number {
		return Identity{}, ErrInvalid
	}
	return Identity{Address: strings.ToLower(w.Address), ChainID: w.ChainID.String(), GenesisHash: strings.ToLower(w.Genesis), Head: w.Head.Number, HeadHash: strings.ToLower(w.Head.Hash)}, nil
}

func mirror(raw json.RawMessage) (Mirror, error) {
	var w struct {
		Number      string            `json:"number"`
		Hash        string            `json:"hash"`
		Healthy     bool              `json:"healthy"`
		Authority   string            `json:"authority"`
		Modes       map[string]string `json:"modes"`
		Validators  []string          `json:"validators"`
		BLSKeys     []string          `json:"blsPublicKeys"`
		GasTip      *string           `json:"gasTip"`
		Blacklisted []string          `json:"blacklisted"`
		Authorized  []string          `json:"authorized"`
	}
	if decode(raw, &w, "number", "hash", "healthy", "authority", "modes", "validators", "blsPublicKeys", "blacklisted", "authorized") != nil || !hasFields(raw, "gasTip") || !quantity(w.Number, 64) || !fixed(w.Hash, 32) || w.Authority != "contract" && w.Authority != "module" || w.GasTip != nil && !quantity(*w.GasTip, 256) || len(w.BLSKeys) > 4096 {
		return Mirror{}, ErrInvalid
	}
	m, err := modes(w.Modes)
	if err != nil {
		return Mirror{}, err
	}
	vs, err := addresses(w.Validators, true)
	if err != nil {
		return Mirror{}, err
	}
	bs, err := addresses(w.Blacklisted, true)
	if err != nil {
		return Mirror{}, err
	}
	as, err := addresses(w.Authorized, true)
	if err != nil {
		return Mirror{}, err
	}
	keys := make([]string, 0, len(w.BLSKeys))
	for _, k := range w.BLSKeys {
		// An empty key is a reported absence, not a verified BLS key.
		if k != "0x" && !fixed(k, 48) {
			return Mirror{}, ErrInvalid
		}
		keys = append(keys, strings.ToLower(k))
	}
	return Mirror{Number: w.Number, Hash: strings.ToLower(w.Hash), Healthy: w.Healthy, Authority: w.Authority, Modes: m, Validators: vs, BLSKeys: keys, GasTip: w.GasTip, Blacklisted: bs, Authorized: as}, nil
}

func faults(raw json.RawMessage, from, to uint64) ([]Fault, error) {
	var rows []json.RawMessage
	if decode(raw, &rows) != nil || rows == nil || len(rows) > maxRows {
		return nil, ErrInvalid
	}
	out := make([]Fault, 0, len(rows))
	for _, row := range rows {
		var w struct {
			Number   string  `json:"number"`
			Kind     string  `json:"kind"`
			Instance string  `json:"instance"`
			What     string  `json:"what"`
			GapFrom  *string `json:"gapFrom"`
			GapTo    *string `json:"gapTo"`
		}
		if decode(row, &w, "number", "kind", "instance", "what") != nil || !within(w.Number, from, to) || !fixed(w.Instance, 20) || len(w.What) > 4096 {
			return nil, ErrInvalid
		}
		f := Fault{Number: w.Number, Kind: w.Kind, Instance: strings.ToLower(w.Instance), Description: summary([]byte(w.What)), GapFrom: w.GapFrom, GapTo: w.GapTo}
		switch w.Kind {
		case "gap":
			if (w.GapFrom == nil) != (w.GapTo == nil) {
				return nil, ErrInvalid
			}
			if w.GapFrom != nil {
				a, aOK := uint64Of(*w.GapFrom)
				b, bOK := uint64Of(*w.GapTo)
				n, _ := uint64Of(w.Number)
				if !aOK || !bOK || b < a || b > n {
					return nil, ErrInvalid
				}
				f.BoundsKnown = true
			}
		case "history", "writes", "flags", "projection", "audit", "epoch":
			if w.GapFrom != nil || w.GapTo != nil {
				return nil, ErrInvalid
			}
		default:
			return nil, ErrInvalid
		}
		out = append(out, f)
	}
	return out, nil
}

func proposal(raw json.RawMessage) (Proposal, error) {
	var w struct {
		ID             string `json:"id"`
		ActionType     string `json:"actionType"`
		Proposer       string `json:"proposer"`
		Status         uint8  `json:"status"`
		Approved       uint32 `json:"approved"`
		Rejected       uint32 `json:"rejected"`
		Required       uint32 `json:"requiredApprovals"`
		ExecutionCount string `json:"executionCount"`
		CallData       string `json:"callData"`
	}
	if decode(raw, &w, "id", "actionType", "proposer", "status", "approved", "rejected", "requiredApprovals", "executionCount", "callData") != nil || !quantity(w.ID, 64) || !quantity(w.ExecutionCount, 64) || !fixed(w.ActionType, 32) || !fixed(w.Proposer, 20) {
		return Proposal{}, ErrInvalid
	}
	data, err := describeHex(w.CallData)
	if err != nil {
		return Proposal{}, err
	}
	return Proposal{ID: w.ID, ActionType: strings.ToLower(w.ActionType), Proposer: strings.ToLower(w.Proposer), Status: w.Status, Approved: w.Approved, Rejected: w.Rejected, RequiredApprovals: w.Required, ExecutionCount: w.ExecutionCount, CallData: data}, nil
}

func state(raw json.RawMessage, addr, number string) (State, error) {
	var w struct {
		Number        string            `json:"number"`
		Instance      string            `json:"instance"`
		Mode          string            `json:"mode"`
		MemberVersion string            `json:"memberVersion"`
		Members       []string          `json:"members"`
		Quorum        string            `json:"quorum"`
		Expiry        string            `json:"proposalExpiry"`
		CurrentID     string            `json:"currentProposalId"`
		Max           string            `json:"maxActiveProposalsPerMember"`
		Proposals     []json.RawMessage `json:"proposals"`
		Validators    []string          `json:"validators"`
		Operators     map[string]string `json:"operators"`
		GasTip        *string           `json:"gasTip"`
		Blacklist     []string          `json:"blacklist"`
		Authorized    []string          `json:"authorizedAccounts"`
		Inexact       bool              `json:"inexact"`
	}
	if decode(raw, &w, "number", "instance", "mode", "memberVersion", "members", "quorum", "proposalExpiry", "currentProposalId", "maxActiveProposalsPerMember", "proposals") != nil || w.Number != number || !strings.EqualFold(w.Instance, addr) || w.Mode != "replay" && w.Mode != "projection-only" || !quantity(w.MemberVersion, 256) || !quantity(w.Quorum, 64) || !quantity(w.Expiry, 256) || !quantity(w.CurrentID, 256) || !quantity(w.Max, 256) || w.GasTip != nil && !quantity(*w.GasTip, 256) || len(w.Proposals) > 4096 || len(w.Operators) > 4096 {
		return State{}, ErrInvalid
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	reported := []string{}
	for _, key := range []string{"validators", "operators", "gasTip", "blacklist", "authorizedAccounts", "inexact"} {
		if value, exists := fields[key]; exists {
			if null(value) {
				if key == "inexact" {
					return State{}, ErrInvalid
				}
				continue
			}
			reported = append(reported, key)
		}
	}
	ms, err := addresses(w.Members, true)
	if err != nil {
		return State{}, err
	}
	vs, err := addresses(w.Validators, false)
	if err != nil {
		return State{}, err
	}
	bs, err := addresses(w.Blacklist, false)
	if err != nil {
		return State{}, err
	}
	as, err := addresses(w.Authorized, false)
	if err != nil {
		return State{}, err
	}
	ops := map[string]string{}
	for k, v := range w.Operators {
		key := strings.ToLower(k)
		if !fixed(k, 20) || !fixed(v, 20) || ops[key] != "" {
			return State{}, ErrInvalid
		}
		ops[key] = strings.ToLower(v)
	}
	ps := make([]Proposal, 0, len(w.Proposals))
	seen := map[string]bool{}
	for _, row := range w.Proposals {
		p, e := proposal(row)
		if e != nil || seen[p.ID] {
			return State{}, ErrInvalid
		}
		seen[p.ID] = true
		ps = append(ps, p)
	}
	return State{ReportedFields: reported, Number: w.Number, Instance: strings.ToLower(w.Instance), Mode: w.Mode, MemberVersion: w.MemberVersion, Members: ms, Quorum: w.Quorum, ProposalExpiry: w.Expiry, CurrentProposalID: w.CurrentID, MaxProposals: w.Max, Proposals: ps, Validators: vs, Operators: ops, GasTip: w.GasTip, Blacklist: bs, Authorized: as, Inexact: w.Inexact}, nil
}
