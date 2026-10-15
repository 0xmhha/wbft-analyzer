package scenario

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

// MaxChangeRequestBytes permits every directed edge in a 256-node model.
const MaxChangeRequestBytes = 2 << 20
const maxChangeNodes = 256

// NetworkChange is a bounded network or node lifecycle intervention. Node is
// used only by cut_outgoing; link changes use explicit edges. Indices refer to fitted
// recorded validators, never private keys or sorted simulated addresses.
type NetworkChange struct {
	Kind           string             `json:"kind" enum:"cut_outgoing,partition,set_link_delay,scale_link_delay,node_lifecycle,set_timing"`
	Node           *int               `json:"node,omitempty" nullable:"false"`
	FromNS         int64              `json:"from_ns"`
	ToNS           int64              `json:"to_ns"`
	Edges          []DirectedEdge     `json:"edges,omitempty"`
	DelayNS        *int64             `json:"delay_ns,omitempty" nullable:"false"`
	Scale          *DelayScale        `json:"scale,omitempty" nullable:"false"`
	Lifecycle      []LifecycleCommand `json:"lifecycle,omitempty"`
	SchedulePolicy string             `json:"schedule_policy,omitempty" enum:"merge,replace_window"`
	Timing         *TimingChange      `json:"timing,omitempty" nullable:"false"`
}
type DirectedEdge struct {
	From *int `json:"from" nullable:"false"`
	To   *int `json:"to" nullable:"false"`
}

// UnmarshalJSON refuses irrelevant fields even when they contain null.
func (c *NetworkChange) UnmarshalJSON(raw []byte) error {
	type wire NetworkChange
	var decoded wire
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	allowed := map[string]bool{"kind": true, "from_ns": true, "to_ns": true}
	switch decoded.Kind {
	case "cut_outgoing":
		allowed["node"] = true
	case "partition":
		allowed["edges"] = true
	case "set_link_delay":
		allowed["edges"] = true
		allowed["delay_ns"] = true
	case "scale_link_delay":
		allowed["edges"] = true
		allowed["scale"] = true
	case "node_lifecycle":
		allowed["lifecycle"] = true
		allowed["schedule_policy"] = true
	case "set_timing":
		allowed["timing"] = true
	default:
		return errNetworkChange
	}
	for key := range fields {
		if !allowed[key] {
			return errNetworkChange
		}
	}
	for _, key := range []string{"kind", "from_ns", "to_ns"} {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errNetworkChange
		}
	}

	normalized, err := NetworkChange(decoded).Normalized()
	if err != nil {
		return err
	}
	*c = normalized
	return nil
}

var errNetworkChange = errors.New("invalid bounded directed network change")

func copyNode(index *int) *int {
	if index == nil {
		return nil
	}
	n := *index
	return &n
}

// Normalized snapshots caller-owned indices and sorts the directed edge set.
// Existing cut_outgoing canonical JSON and hashes remain unchanged.
func (c NetworkChange) Normalized() (NetworkChange, error) {
	if c.FromNS < 0 || c.ToNS <= c.FromNS || c.ToNS > int64(24*time.Hour) {
		return NetworkChange{}, errNetworkChange
	}
	if c.Kind != "node_lifecycle" && (c.Lifecycle != nil || c.SchedulePolicy != "") {
		return NetworkChange{}, errNetworkChange
	}
	if c.Kind != "set_timing" && c.Timing != nil {
		return NetworkChange{}, errNetworkChange
	}
	switch c.Kind {
	case "set_timing":
		return normalizeTimingChange(c)
	case "node_lifecycle":
		return normalizeLifecycle(c)
	case "cut_outgoing":
		if c.Node == nil || *c.Node < 0 || *c.Node >= maxChangeNodes || c.Edges != nil || c.DelayNS != nil || c.Scale != nil {
			return NetworkChange{}, errNetworkChange
		}
		c.Node = copyNode(c.Node)
	case "partition", "set_link_delay", "scale_link_delay":
		if c.Node != nil || len(c.Edges) == 0 || len(c.Edges) > maxChangeNodes*(maxChangeNodes-1) {
			return NetworkChange{}, errNetworkChange
		}
		edges := make([]DirectedEdge, len(c.Edges))
		for i, e := range c.Edges {
			if e.From == nil || e.To == nil || *e.From < 0 || *e.To < 0 || *e.From >= maxChangeNodes || *e.To >= maxChangeNodes || *e.From == *e.To {
				return NetworkChange{}, errNetworkChange
			}
			edges[i] = DirectedEdge{From: copyNode(e.From), To: copyNode(e.To)}
		}
		slices.SortFunc(edges, func(a, b DirectedEdge) int {
			if n := cmp.Compare(*a.From, *b.From); n != 0 {
				return n
			}
			return cmp.Compare(*a.To, *b.To)
		})
		for i := 1; i < len(edges); i++ {
			if *edges[i-1].From == *edges[i].From && *edges[i-1].To == *edges[i].To {
				return NetworkChange{}, errNetworkChange
			}
		}
		c.Edges = edges
		switch c.Kind {
		case "partition":
			if c.DelayNS != nil || c.Scale != nil {
				return NetworkChange{}, errNetworkChange
			}
		case "set_link_delay":
			if c.DelayNS == nil || *c.DelayNS < 0 || time.Duration(*c.DelayNS) > maxLinkDelay || c.Scale != nil {
				return NetworkChange{}, errNetworkChange
			}
			delay := *c.DelayNS
			c.DelayNS = &delay
		case "scale_link_delay":
			if c.Scale == nil || c.Scale.Denominator == 0 || c.DelayNS != nil {
				return NetworkChange{}, errNetworkChange
			}
			ratio := *c.Scale
			divisor := gcd(ratio.Numerator, ratio.Denominator)
			ratio.Numerator /= divisor
			ratio.Denominator /= divisor
			c.Scale = &ratio
		}

	default:
		return NetworkChange{}, errNetworkChange
	}
	return c, nil
}

func (c NetworkChange) ValidateFor(nodes int, duration time.Duration) error {
	normalized, err := c.Normalized()
	if err != nil || nodes < 2 || nodes > maxChangeNodes || duration <= 0 || time.Duration(c.ToNS) > duration {
		return errNetworkChange
	}
	if (normalized.IsLinkDelay() || normalized.Kind == "set_timing") && (normalized.FromNS != 0 || time.Duration(normalized.ToNS) != duration) {
		return errNetworkChange
	}
	if normalized.Node != nil && *normalized.Node >= nodes {
		return errNetworkChange
	}
	for _, e := range normalized.Edges {
		if *e.From >= nodes || *e.To >= nodes {
			return errNetworkChange
		}
	}
	for _, command := range normalized.Lifecycle {
		if *command.Node >= nodes {
			return errNetworkChange
		}
	}
	if normalized.Timing != nil {
		for _, node := range normalized.Timing.Nodes {
			if *node.Node >= nodes {
				return errNetworkChange
			}
		}
	}
	return nil
}

// ApplyNetworkChange uses official directed partitions or full-run link delays.
// It leaves reverse edges and the caller's baseline scenario unchanged.
func ApplyNetworkChange(sc sim.Scenario, change NetworkChange) (sim.Scenario, string, error) {
	if err := change.ValidateFor(len(sc.Validators), sc.Until.Duration); err != nil {
		return sc, "", err
	}
	normalized, err := change.Normalized()
	if err != nil {
		return sc, "", err
	}
	if normalized.IsLinkDelay() {
		return applyLinkDelay(sc, normalized)
	}
	if normalized.Kind == "node_lifecycle" {
		return applyNodeLifecycle(sc, normalized)
	}
	if normalized.Kind == "set_timing" {
		return applyTimingChange(sc, normalized)
	}
	cut := [][2]types.Address{}
	if normalized.Kind == "cut_outgoing" {
		from := sc.Validators[*normalized.Node].Address()
		for i, v := range sc.Validators {
			if i != *normalized.Node {
				cut = append(cut, [2]types.Address{from, v.Address()})
			}
		}
	} else {
		for _, e := range normalized.Edges {
			cut = append(cut, [2]types.Address{sc.Validators[*e.From].Address(), sc.Validators[*e.To].Address()})
		}
	}
	sc.Partitions = append(append([]sim.Partition(nil), sc.Partitions...), sim.Partition{From: time.Duration(normalized.FromNS), To: time.Duration(normalized.ToNS), DirectedCut: cut})
	_, hash, err := normalized.Canonical()
	return sc, hash, err
}

func (c NetworkChange) Canonical() ([]byte, string, error) {
	normalized, err := c.Normalized()
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}
