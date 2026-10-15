package scenario

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// Synthetic nodes use test keys and a declared, unmeasured runtime model.
// This preset means zero processing cost, independent fake application jobs,
// a shared manual clock without skew, fresh signing state, and optional
// restart-safety rules off.
const SyntheticCompatModel = "unmeasured_compat"

var membershipAlias = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

type MembershipChange struct {
	Policy string            `json:"policy" enum:"merge,replace_from_first_epoch"`
	Nodes  []MembershipNode  `json:"nodes"`
	Links  []MembershipLink  `json:"links"`
	Epochs []MembershipEpoch `json:"epochs"`
}

type MembershipNode struct {
	Alias       string               `json:"alias"`
	Model       string               `json:"model" enum:"unmeasured_compat"`
	StartNS     int64                `json:"start_ns,string"`
	Timing      MembershipTiming     `json:"timing"`
	BuildDelay  []MembershipDuration `json:"build_delay"`
	ImportDelay []MembershipDuration `json:"import_delay"`
}

// Synthetic nodes have no measured timing to inherit, so all values are
// required, including an explicit zero to remove the request-timeout cap.
type MembershipTiming struct {
	RequestTimeoutSeconds    uint64 `json:"request_timeout_seconds,string"`
	BlockPeriodSeconds       uint64 `json:"block_period_seconds,string"`
	MaxRequestTimeoutSeconds uint64 `json:"max_request_timeout_seconds,string"`
}

func (v MembershipTiming) values() TimingValues {
	return TimingValues{RequestTimeoutSeconds: &v.RequestTimeoutSeconds, BlockPeriodSeconds: &v.BlockPeriodSeconds, MaxRequestTimeoutSeconds: &v.MaxRequestTimeoutSeconds}
}

func (v *MembershipTiming) UnmarshalJSON(raw []byte) error {
	type wire MembershipTiming
	var decoded wire
	if err := decodeTimingObject(raw, &decoded, map[string]bool{"request_timeout_seconds": true, "block_period_seconds": true, "max_request_timeout_seconds": true}, "request_timeout_seconds", "block_period_seconds", "max_request_timeout_seconds"); err != nil {
		return err
	}
	*v = MembershipTiming(decoded)
	return nil
}

type MembershipDuration struct {
	NS int64 `json:"ns,string"`
}

type MembershipLink struct {
	From    int                  `json:"from"`
	To      int                  `json:"to"`
	Delays  []MembershipDuration `json:"delays"`
	LossPPM uint64               `json:"loss_ppm,string"`
}

type MembershipEpoch struct {
	Block      uint64 `json:"block,string"`
	Candidates []int  `json:"candidates"`
}

func (v *MembershipChange) UnmarshalJSON(raw []byte) error {
	type wire MembershipChange
	var decoded wire
	if err := decodeTimingObject(raw, &decoded, map[string]bool{"policy": true, "nodes": true, "links": true, "epochs": true}, "policy", "nodes", "links", "epochs"); err != nil {
		return err
	}
	*v = MembershipChange(decoded)
	return nil
}

func (v *MembershipNode) UnmarshalJSON(raw []byte) error {
	type wire MembershipNode
	var decoded wire
	if err := decodeTimingObject(raw, &decoded, map[string]bool{"alias": true, "model": true, "start_ns": true, "timing": true, "build_delay": true, "import_delay": true}, "alias", "model", "start_ns", "timing", "build_delay", "import_delay"); err != nil {
		return err
	}
	*v = MembershipNode(decoded)
	return nil
}

func (v *MembershipDuration) UnmarshalJSON(raw []byte) error {
	type wire MembershipDuration
	var decoded wire
	if err := decodeTimingObject(raw, &decoded, map[string]bool{"ns": true}, "ns"); err != nil {
		return err
	}
	*v = MembershipDuration(decoded)
	return nil
}

func (v *MembershipLink) UnmarshalJSON(raw []byte) error {
	type wire MembershipLink
	var decoded wire
	if err := decodeTimingObject(raw, &decoded, map[string]bool{"from": true, "to": true, "delays": true, "loss_ppm": true}, "from", "to", "delays", "loss_ppm"); err != nil {
		return err
	}
	*v = MembershipLink(decoded)
	return nil
}

func (v *MembershipEpoch) UnmarshalJSON(raw []byte) error {
	type wire MembershipEpoch
	var decoded wire
	if err := decodeTimingObject(raw, &decoded, map[string]bool{"block": true, "candidates": true}, "block", "candidates"); err != nil {
		return err
	}
	*v = MembershipEpoch(decoded)
	return nil
}

func membershipSamples(samples []MembershipDuration, limit time.Duration) ([]MembershipDuration, error) {
	if len(samples) == 0 || len(samples) > 256 {
		return nil, errNetworkChange
	}
	for _, sample := range samples {
		if sample.NS < 0 || time.Duration(sample.NS) > limit {
			return nil, errNetworkChange
		}
	}
	return slices.Clone(samples), nil
}

func normalizeMembership(c NetworkChange) (NetworkChange, error) {
	if c.FromNS != 0 || c.Membership == nil || c.Node != nil || c.Edges != nil || c.DelayNS != nil || c.Scale != nil || c.Messages != nil || c.Timing != nil || c.Lifecycle != nil || c.SchedulePolicy != "" {
		return NetworkChange{}, errNetworkChange
	}
	m := c.Membership
	if m.Policy != "merge" && m.Policy != "replace_from_first_epoch" || m.Nodes == nil || len(m.Nodes) > maxChangeNodes-2 || m.Links == nil || len(m.Links) > maxChangeNodes*(maxChangeNodes-1) || len(m.Epochs) == 0 || len(m.Epochs) > 10000 {
		return NetworkChange{}, errNetworkChange
	}
	out := &MembershipChange{Policy: m.Policy, Nodes: make([]MembershipNode, len(m.Nodes)), Links: make([]MembershipLink, len(m.Links)), Epochs: make([]MembershipEpoch, len(m.Epochs))}
	aliases := map[string]bool{}
	for i, node := range m.Nodes {
		if !membershipAlias.MatchString(node.Alias) || aliases[node.Alias] || node.Model != SyntheticCompatModel || node.StartNS < 0 || node.StartNS >= c.ToNS || node.Timing.RequestTimeoutSeconds == 0 || node.Timing.BlockPeriodSeconds == 0 {
			return NetworkChange{}, errNetworkChange
		}
		aliases[node.Alias] = true
		var err error
		_, err = cloneTimingValues(node.Timing.values(), time.Duration(c.ToNS))
		if err != nil {
			return NetworkChange{}, err
		}
		node.BuildDelay, err = membershipSamples(node.BuildDelay, time.Hour)
		if err != nil {
			return NetworkChange{}, err
		}
		node.ImportDelay, err = membershipSamples(node.ImportDelay, time.Hour)
		if err != nil {
			return NetworkChange{}, err
		}
		out.Nodes[i] = node
	}
	for i, link := range m.Links {
		if link.From < 0 || link.To < 0 || link.From >= maxChangeNodes || link.To >= maxChangeNodes || link.From == link.To || link.LossPPM >= 1000000 {
			return NetworkChange{}, errNetworkChange
		}
		var err error
		link.Delays, err = membershipSamples(link.Delays, maxLinkDelay)
		if err != nil {
			return NetworkChange{}, err
		}
		out.Links[i] = link
	}
	slices.SortFunc(out.Links, func(a, b MembershipLink) int {
		if n := cmp.Compare(a.From, b.From); n != 0 {
			return n
		}
		return cmp.Compare(a.To, b.To)
	})
	for i := 1; i < len(out.Links); i++ {
		if out.Links[i-1].From == out.Links[i].From && out.Links[i-1].To == out.Links[i].To {
			return NetworkChange{}, errNetworkChange
		}
	}
	for i, e := range m.Epochs {
		if e.Block == 0 || e.Block > 10000 || len(e.Candidates) == 0 || len(e.Candidates) > maxChangeNodes {
			return NetworkChange{}, errNetworkChange
		}
		e.Candidates = slices.Clone(e.Candidates)
		seen := map[int]bool{}
		for _, n := range e.Candidates {
			if n < 0 || n >= maxChangeNodes || seen[n] {
				return NetworkChange{}, errNetworkChange
			}
			seen[n] = true
		}
		out.Epochs[i] = e
	}
	slices.SortFunc(out.Epochs, func(a, b MembershipEpoch) int { return cmp.Compare(a.Block, b.Block) })
	for i := 1; i < len(out.Epochs); i++ {
		if out.Epochs[i-1].Block == out.Epochs[i].Block {
			return NetworkChange{}, errNetworkChange
		}
	}
	c.Membership = out
	return c, nil
}

// Every new ordered link is explicit. Recorded-to-recorded links cannot be
// replaced by this intervention, even when the requested value is identical.
func validateMembershipNodes(m *MembershipChange, original int) error {
	total := original + len(m.Nodes)
	if original < 2 || total > maxChangeNodes || len(m.Links) != total*(total-1)-original*(original-1) {
		return errNetworkChange
	}
	for _, link := range m.Links {
		if link.From >= total || link.To >= total || link.From < original && link.To < original {
			return errNetworkChange
		}
	}
	used := map[int]bool{}
	for _, e := range m.Epochs {
		for _, n := range e.Candidates {
			if n >= total {
				return errNetworkChange
			}
			used[n] = true
		}
	}
	for n := original; n < total; n++ {
		if !used[n] {
			return errNetworkChange
		}
	}
	return nil
}

type MembershipScope struct {
	Nodes                   int
	EpochLength, StopHeight uint64
	Duration                time.Duration
}

func MembershipBounds(sc sim.Scenario) MembershipScope {
	return MembershipScope{Nodes: len(sc.Validators), EpochLength: sc.Params.EpochLength, StopHeight: sc.Until.Height, Duration: sc.Until.Duration}
}

func (c NetworkChange) ValidateMembershipBounds(scope MembershipScope) error {
	if c.Kind != "synthetic_membership" {
		return nil
	}
	n, err := c.Normalized()
	if err != nil || n.ValidateFor(scope.Nodes, scope.Duration) != nil || scope.EpochLength == 0 || scope.StopHeight == 0 || scope.StopHeight > 10000 {
		return errNetworkChange
	}
	for _, e := range n.Membership.Epochs {
		if e.Block > scope.StopHeight || e.Block%scope.EpochLength != 0 {
			return errNetworkChange
		}
	}
	return nil
}

type SyntheticNodeIdentity struct {
	Index   int    `json:"index"`
	Alias   string `json:"alias"`
	Address string `json:"simulated_address"`
}

type MembershipEffect struct {
	Source               string                  `json:"source"`
	BaselineSHA256       string                  `json:"baseline_execution_sha256"`
	CounterfactualSHA256 string                  `json:"counterfactual_execution_sha256"`
	OriginalNodes        int                     `json:"original_nodes"`
	Genesis              int                     `json:"genesis_validators"`
	SyntheticNodes       []SyntheticNodeIdentity `json:"synthetic_nodes"`
	OriginalEpochs       []MembershipEpoch       `json:"original_epochs"`
	RetainedEpochs       []MembershipEpoch       `json:"retained_epochs"`
	RemovedEpochs        []MembershipEpoch       `json:"removed_epochs"`
	EffectiveEpochs      []MembershipEpoch       `json:"effective_epochs"`
	Assumptions          []string                `json:"assumptions"`
}

func membershipEpoch(e sim.EpochChange) MembershipEpoch {
	return MembershipEpoch{Block: e.Block, Candidates: slices.Clone(e.Candidates)}
}

// ApplyMembershipChange delegates candidate selection, diligence, transport,
// synchronization and signing to the official simulator and WBFT core.
func ApplyMembershipChange(sc sim.Scenario, c NetworkChange) (sim.Scenario, *MembershipEffect, string, error) {
	n, err := c.Normalized()
	if err != nil || n.Kind != "synthetic_membership" || n.ValidateMembershipBounds(MembershipBounds(sc)) != nil || len(sc.Nodes) != len(sc.Validators) {
		return sc, nil, "", errNetworkChange
	}
	baseline, err := ExecutionHash(sc)
	if err != nil {
		return sc, nil, "", err
	}
	count := len(sc.Validators)
	genesis := sc.Genesis
	if genesis == 0 {
		genesis = count
	}
	if genesis < 2 || genesis > count {
		return sc, nil, "", errNetworkChange
	}
	out := &MembershipEffect{Source: "declared_synthetic_membership/1", BaselineSHA256: baseline, OriginalNodes: count, Genesis: genesis, SyntheticNodes: []SyntheticNodeIdentity{}, OriginalEpochs: []MembershipEpoch{}, RetainedEpochs: []MembershipEpoch{}, RemovedEpochs: []MembershipEpoch{}, EffectiveEpochs: []MembershipEpoch{}, Assumptions: []string{
		"requested_candidates_are_not_observed_validator_selection",
		"membership_changes_are_synthetic_not_recorded_network_events",
		"new_keys_are_deterministic_test_keys_without_recorded_identity",
		"new_link_samples_and_loss_are_declared_unmeasured",
	}}
	m := n.Membership
	if len(m.Nodes) > 0 {
		out.Assumptions = append(out.Assumptions, "synthetic_nodes_use_compat_core_without_optional_rules_or_wal_replay", "synthetic_nodes_have_fresh_signing_state_and_no_takeover_floor", "synthetic_nodes_share_manual_clock_with_zero_skew", "synthetic_nodes_use_zero_processing_cost_and_independent_fake_app_jobs", "synthetic_node_timing_and_app_samples_are_declared_unmeasured")
	}
	sc.Validators = slices.Clone(sc.Validators)
	sc.Nodes = slices.Clone(sc.Nodes)
	sc.Links = slices.Clone(sc.Links)
	known := map[types.Address]bool{}
	for _, v := range sc.Validators {
		known[v.Address()] = true
	}
	for i, node := range m.Nodes {
		key, err := sim.NewValidator(keccak.Sum256Bytes([]byte(fmt.Sprintf("wbft-synthetic-membership-test-key/1/%s/%d/%s", baseline, count+i, node.Alias))))
		if err != nil || known[key.Address()] {
			return sc, nil, "", errNetworkChange
		}
		known[key.Address()] = true
		sc.Validators = append(sc.Validators, key)
		spec := sim.NodeSpec{Profile: "compat", StartAfter: time.Duration(node.StartNS), Timing: node.Timing.values().params(), BuildDelay: membershipDurations(node.BuildDelay), ImportDelay: membershipDurations(node.ImportDelay)}
		sc.Nodes = append(sc.Nodes, spec)
		out.SyntheticNodes = append(out.SyntheticNodes, SyntheticNodeIdentity{Index: count + i, Alias: node.Alias, Address: key.Address().Hex()})
	}
	for _, link := range m.Links {
		sc.Links = append(sc.Links, sim.Link{From: sc.Validators[link.From].Address(), To: sc.Validators[link.To].Address(), Delay: membershipDurations(link.Delays), Loss: float64(link.LossPPM) / 1000000})
	}
	// Appending nodes must never make them genesis validators through Genesis=0.
	sc.Genesis = genesis
	requested := map[uint64]bool{}
	for _, e := range m.Epochs {
		requested[e.Block] = true
	}
	epochs := []sim.EpochChange{}
	var previous uint64
	for _, e := range sc.Epochs {
		if e.Block == 0 || e.Block <= previous || e.Block%sc.Params.EpochLength != 0 {
			return sc, nil, "", errNetworkChange
		}
		previous = e.Block
		out.OriginalEpochs = append(out.OriginalEpochs, membershipEpoch(e))
		if requested[e.Block] || m.Policy == "replace_from_first_epoch" && e.Block >= m.Epochs[0].Block {
			out.RemovedEpochs = append(out.RemovedEpochs, membershipEpoch(e))
		} else {
			epochs = append(epochs, sim.EpochChange{Block: e.Block, Candidates: slices.Clone(e.Candidates)})
			out.RetainedEpochs = append(out.RetainedEpochs, membershipEpoch(e))
		}
	}
	for _, e := range m.Epochs {
		epochs = append(epochs, sim.EpochChange{Block: e.Block, Candidates: slices.Clone(e.Candidates)})
	}
	slices.SortFunc(epochs, func(a, b sim.EpochChange) int { return cmp.Compare(a.Block, b.Block) })
	sc.Epochs = epochs
	for _, e := range epochs {
		out.EffectiveEpochs = append(out.EffectiveEpochs, membershipEpoch(e))
	}
	out.CounterfactualSHA256, err = ExecutionHash(sc)
	if err != nil {
		return sc, nil, "", err
	}
	_, hash, err := n.Canonical()
	return sc, out, hash, err
}

func membershipDurations(samples []MembershipDuration) []time.Duration {
	out := make([]time.Duration, len(samples))
	for i, d := range samples {
		out[i] = time.Duration(d.NS)
	}
	return out
}
