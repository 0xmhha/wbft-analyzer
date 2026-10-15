package scenario

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/0xmhha/wbft/conformance/sim"
)

type SeedLifecycleObservations struct {
	Source string          `json:"source"`
	Starts []SeedNodeStart `json:"node_starts"`
}

type SeedNodeStart struct {
	Node       int    `json:"node"`
	AtNS       int64  `json:"at_ns"`
	Run        string `json:"run"`
	Status     string `json:"status" enum:"started,refused"`
	WALRecords *int   `json:"wal_records,omitempty" nullable:"false"`
}

// Observations come from official simulator events, never from requested times.
// A request after the simulator's stop condition produces no synthetic receipt.
func observedNodeStarts(sc sim.Scenario, result *sim.Result) (*SeedLifecycleObservations, error) {
	out := &SeedLifecycleObservations{Source: "official_simulator_node_start_events/1", Starts: []SeedNodeStart{}}
	indices := map[string]int{}
	for i, v := range sc.Validators {
		indices[strings.ToLower(v.Address().Hex())] = i
	}
	for _, data := range result.Events {
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var record struct {
				Kind     string  `json:"kind"`
				Node     string  `json:"node"`
				AtNS     *int64  `json:"t_mono_ns"`
				Run      string  `json:"run"`
				Refused  *string `json:"refused"`
				Recovery *struct {
					Records int `json:"records"`
				} `json:"wal_recovery"`
			}
			if err := json.Unmarshal(line, &record); err != nil {
				return nil, err
			}
			if record.Kind != "NODE_START" {
				continue
			}
			node, found := indices[strings.ToLower(record.Node)]
			if !found || record.AtNS == nil || *record.AtNS < 0 || *record.AtNS > int64(result.SimTime) || record.Run == "" {
				return nil, errors.New("invalid simulator node start observation")
			}
			start := SeedNodeStart{Node: node, AtNS: *record.AtNS, Run: record.Run, Status: "started"}
			if record.Refused != nil {
				start.Status = "refused"
			} else {
				if record.Recovery == nil || record.Recovery.Records < 0 {
					return nil, errors.New("simulator node start lacks WAL recovery evidence")
				}
				count := record.Recovery.Records
				start.WALRecords = &count
			}
			out.Starts = append(out.Starts, start)
		}
	}
	slices.SortFunc(out.Starts, func(a, b SeedNodeStart) int {
		if order := cmp.Compare(a.AtNS, b.AtNS); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Node, b.Node); order != 0 {
			return order
		}
		return cmp.Compare(a.Run, b.Run)
	})
	return out, nil
}
