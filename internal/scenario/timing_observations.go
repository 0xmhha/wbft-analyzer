package scenario

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

const timingArmsPerNode = 32

type SeedTimingObservations struct {
	Source         string                     `json:"source"`
	Sampling       string                     `json:"timer_sampling"`
	Configurations []SeedJournalConfiguration `json:"journal_configurations"`
	Coverage       []SeedTimerCoverage        `json:"timer_coverage"`
	Arms           []SeedTimerArm             `json:"round_timer_arms"`
}

type SeedJournalConfiguration struct {
	Node       int                 `json:"node"`
	Run        string              `json:"run"`
	EngineRun  uint64              `json:"engine_run,string"`
	SHA256     string              `json:"chain_config_sha256"`
	Segments   int                 `json:"journal_segments"`
	Parameters TimingConfiguration `json:"parameters"`
}

type SeedTimerCoverage struct {
	Node     int    `json:"node"`
	Total    uint64 `json:"total_round_timer_arms,string"`
	Retained int    `json:"retained_round_timer_arms"`
}

type SeedTimerArm struct {
	Node       int    `json:"node"`
	Run        string `json:"run"`
	EngineRun  uint64 `json:"engine_run,string"`
	Generation uint64 `json:"generation,string"`
	AtNS       int64  `json:"at_ns,string"`
	Height     string `json:"height"`
	Round      string `json:"round"`
	DurationMS int64  `json:"duration_ms,string"`
	DeadlineNS *int64 `json:"deadline_ns,string,omitempty" nullable:"false"`
	Rearmed    bool   `json:"rearmed"`
}

func simulateTimingSeed(ctx context.Context, sc sim.Scenario, retain bool) (*sim.Result, *SeedTimingObservations, error) {
	if !retain {
		result, err := sim.Run(ctx, sc, sim.Output{})
		return result, nil, err
	}
	// Read the simulator's exported journal through its public reader. This
	// evidence is local to one seed and never replaces a registered recording.
	dir, err := os.MkdirTemp("", "wbft-analyzer-timing-")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	result, err := sim.Run(ctx, sc, sim.Output{JournalDir: dir})
	if err != nil {
		return nil, nil, err
	}
	observations, err := observedTiming(sc, result, dir)
	return result, observations, err
}

func timerArmOrder(a, b SeedTimerArm) int {
	if n := cmp.Compare(a.AtNS, b.AtNS); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Node, b.Node); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Run, b.Run); n != 0 {
		return n
	}
	if n := cmp.Compare(a.EngineRun, b.EngineRun); n != 0 {
		return n
	}
	return cmp.Compare(a.Generation, b.Generation)
}

// Retain the first and last 16 arms per node, in the declared event order.
// Counts disclose omitted arms; a bounded sample never claims a complete trace.
func retainTimingArm(rows []SeedTimerArm, arm SeedTimerArm) []SeedTimerArm {
	rows = append(rows, arm)
	slices.SortStableFunc(rows, timerArmOrder)
	if len(rows) > timingArmsPerNode {
		rows = append(rows[:timingArmsPerNode/2], rows[len(rows)-timingArmsPerNode/2:]...)
	}
	return rows
}

func observedTiming(sc sim.Scenario, result *sim.Result, dir string) (*SeedTimingObservations, error) {
	if len(sc.Nodes) != len(sc.Validators) {
		return nil, errNetworkChange
	}
	out := &SeedTimingObservations{Source: "simulator_journal_segments_and_timer_events/1", Sampling: "first_16_and_last_16_per_node_by_time_node_run_engine_generation", Configurations: []SeedJournalConfiguration{}, Coverage: []SeedTimerCoverage{}, Arms: []SeedTimerArm{}}
	indices := map[string]int{}
	for i, v := range sc.Validators {
		indices[strings.ToLower(v.Address().Hex())] = i
		if len(result.Journals[v.Address()]) == 0 {
			continue
		}
		journalDir := filepath.Join(dir, strings.TrimPrefix(strings.ToLower(v.Address().Hex()), "0x"))
		records, err := journal.ReadAll(nil, journalDir)
		if err != nil {
			return nil, err
		}
		expected, err := resolvedTiming(sc.Params, sc.Nodes[i].Timing, sc.Until.Duration)
		if err != nil {
			return nil, err
		}
		seen := map[string]int{}
		for _, record := range records {
			segment, ok := record.Body.(*journal.SegmentRec)
			if !ok {
				continue
			}
			if segment.Self != v.Address() || segment.Run == "" {
				return nil, errors.New("simulator journal node or run identity mismatch")
			}
			cfg, err := segment.Core.Configuration()
			if err != nil {
				return nil, err
			}
			p := cfg.ConfigAt(types.HeightFromUint64(1))
			actual := TimingConfiguration{RequestTimeoutMS: p.RequestTimeoutMs, BlockPeriodSeconds: p.BlockPeriodSeconds, MaxRequestTimeoutSeconds: p.MaxRequestTimeoutSeconds}
			if actual != expected {
				return nil, errors.New("simulator journal timing differs from resolved node configuration")
			}
			digest := sha256.Sum256(segment.Core.ChainConfig)
			hash := hex.EncodeToString(digest[:])
			key := fmt.Sprintf("%s/%d", segment.Run, segment.EngineRun)
			if at, found := seen[key]; found {
				if out.Configurations[at].SHA256 != hash {
					return nil, errors.New("simulator journal configuration changes within an engine run")
				}
				out.Configurations[at].Segments++
			} else {
				seen[key] = len(out.Configurations)
				out.Configurations = append(out.Configurations, SeedJournalConfiguration{Node: i, Run: segment.Run, EngineRun: segment.EngineRun, SHA256: hash, Segments: 1, Parameters: actual})
			}
		}
	}
	rows := make([][]SeedTimerArm, len(sc.Validators))
	total := make([]uint64, len(sc.Validators))
	for _, data := range result.Events {
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var event struct {
				Kind, Node, Run, Timer string
				EngineRun              *uint64 `json:"engine_run"`
				Generation             *uint64 `json:"gen"`
				AtNS                   *int64  `json:"t_mono_ns"`
				DurationMS             *int64  `json:"duration_ms"`
				DeadlineNS             *int64  `json:"deadline_mono_ns"`
				Rearmed                bool    `json:"rearmed"`
				View                   *struct {
					Seq, Round string
				}
			}
			if err := json.Unmarshal(line, &event); err != nil {
				return nil, err
			}
			if event.Kind != "TIMER_ARM" || event.Timer != "round" {
				continue
			}
			node, found := indices[strings.ToLower(event.Node)]
			if !found || event.Run == "" || event.AtNS == nil || *event.AtNS < 0 || *event.AtNS > int64(result.SimTime) || event.EngineRun == nil || event.Generation == nil || event.DurationMS == nil || *event.DurationMS < 0 || event.View == nil || event.View.Seq == "" || event.View.Round == "" || event.DeadlineNS == nil && !event.Rearmed {
				return nil, errors.New("invalid simulator round timer observation")
			}
			arm := SeedTimerArm{Node: node, Run: event.Run, EngineRun: *event.EngineRun, Generation: *event.Generation, AtNS: *event.AtNS, Height: event.View.Seq, Round: event.View.Round, DurationMS: *event.DurationMS, DeadlineNS: event.DeadlineNS, Rearmed: event.Rearmed}
			total[node]++
			rows[node] = retainTimingArm(rows[node], arm)
		}
	}
	for node := range rows {
		out.Coverage = append(out.Coverage, SeedTimerCoverage{Node: node, Total: total[node], Retained: len(rows[node])})
		out.Arms = append(out.Arms, rows[node]...)
	}
	slices.SortStableFunc(out.Arms, timerArmOrder)
	slices.SortFunc(out.Configurations, func(a, b SeedJournalConfiguration) int {
		if n := cmp.Compare(a.Node, b.Node); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Run, b.Run); n != 0 {
			return n
		}
		return cmp.Compare(a.EngineRun, b.EngineRun)
	})
	return out, nil
}
