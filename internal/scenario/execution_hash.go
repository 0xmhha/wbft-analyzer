package scenario

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

// ExecutionHash pins executable simulation options without serializing keys.
// Each public validator identity is rederived from the supplied test key to
// reject stale cached addresses after a caller changed the key bytes.
func ExecutionHash(sc sim.Scenario) (string, error) {
	if len(sc.Adversaries) > 0 || len(sc.Faults) > 0 || len(sc.Disk) > 0 || sc.Log != nil || sc.LogOut != nil || len(sc.App.BadProposals) > 0 || len(sc.App.FailedImports) > 0 {
		return "", errors.New("unsupported execution identity")
	}
	addresses := []types.Address{}
	for _, v := range sc.Validators {
		actual, err := sim.NewValidator(v.ECDSA)
		if err != nil || !bytes.Equal(actual.Address().Bytes(), v.Address().Bytes()) {
			return "", errors.New("simulation key identity changed")
		}
		addresses = append(addresses, v.Address())
	}
	type node struct {
		Timing                  *sim.TimingParams      `json:"Timing,omitempty"`
		Processing              *sim.ProcessingProfile `json:"Processing,omitempty"`
		StartAfter              int64
		BuildDelay, ImportDelay []int64
		Improvements            uint64
		BacklogLimit            int
		Profile                 string
		ReplayWAL               bool
		ClockSkew               int64
		TakeoverGuard           bool
		WALSegmentBytes         int64
	}
	nodes := []node{}
	for _, n := range sc.Nodes {
		x := node{Timing: n.Timing, Processing: n.Processing, StartAfter: int64(n.StartAfter), Improvements: uint64(n.Options.Improvements), BacklogLimit: n.Options.BacklogLimit, Profile: n.Profile, ReplayWAL: n.ReplayWAL, ClockSkew: int64(n.ClockSkew), TakeoverGuard: n.TakeoverGuard, WALSegmentBytes: n.WALSegmentBytes, BuildDelay: []int64{}, ImportDelay: []int64{}}
		for _, d := range n.BuildDelay {
			x.BuildDelay = append(x.BuildDelay, int64(d))
		}
		for _, d := range n.ImportDelay {
			x.ImportDelay = append(x.ImportDelay, int64(d))
		}
		nodes = append(nodes, x)
	}
	raw, err := json.Marshal(struct {
		WallOrigin  string
		Validators  []types.Address
		Genesis     int
		Nodes       []node
		Params      sim.Params
		DefaultLink sim.Link
		Links       []sim.Link
		Partitions  []sim.Partition
		Schedule    []sim.NodeEvent
		App         sim.AppModel
		Epochs      []sim.EpochChange
		Until       sim.Stop
		NoProgress  bool
	}{scenarioWallOrigin(sc).Format(time.RFC3339Nano), addresses, sc.Genesis, nodes, sc.Params, sc.DefaultLink, sc.Links, sc.Partitions, sc.Schedule, sc.App, sc.Epochs, sc.Until, sc.NoProgress})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Resolve a default once before execution rather than reading mutable global
// clock state from each node. Explicit recorded origins never use that state.
func scenarioWallOrigin(sc sim.Scenario) time.Time {
	origin := sc.WallOrigin
	if origin.IsZero() {
		origin = sim.Epoch
	}
	return origin.UTC().Round(0)
}
