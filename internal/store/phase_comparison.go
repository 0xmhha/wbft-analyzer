package store

import (
	"context"
	"errors"
	"math/big"

	"github.com/0xmhha/wbft-analyzer/internal/derive/baseline"
	"github.com/0xmhha/wbft-analyzer/internal/derive/latency"
	"github.com/jackc/pgx/v5"
)

type PhaseHeightCoverage struct {
	Node     string `json:"node"`
	Profile  string `json:"profile"`
	Observed int64  `json:"observed_heights"`
	Missing  int64  `json:"unobserved_heights"`
}
type PhaseComparisonNetwork struct {
	ID          int64  `json:"id"`
	ChainID     string `json:"chain_id"`
	GenesisHash string `json:"genesis_hash"`
	Name        string `json:"name"`
}
type PhaseComparisonRun struct {
	Network           PhaseComparisonNetwork `json:"network"`
	Dataset           int64                  `json:"dataset"`
	Name              string                 `json:"name"`
	Summary           latency.Summary        `json:"summary"`
	Coverage          []PhaseHeightCoverage  `json:"coverage"`
	Examples          []latency.Sample       `json:"examples"`
	ExamplesTruncated bool                   `json:"examples_truncated"`
}
type PhaseComparison struct {
	Rounds         baseline.Summary     `json:"rounds"`
	Metric         string               `json:"metric"`
	Runs           []PhaseComparisonRun `json:"runs"`
	ContextRecords int64                `json:"context_records"`
	Method         string               `json:"method"`
}

// PhaseComparison uses logical height intervals rather than shared wall-clock
// windows. Percentiles are computed separately from each run's raw samples.
func (s *Store) PhaseComparison(ctx context.Context, network int64, ids []int64, from, to, node, metric string, crossNetwork bool) (PhaseComparison, error) {
	out := PhaseComparison{Metric: metric, Runs: []PhaseComparisonRun{}, Method: "same numeric full-height interval; independent network/run/node/profile/clock distributions; nearest-rank percentiles from each group's raw valid samples; no percentile averaging or network-decision pooling; unobserved heights are not zero latency; at most 64 first-per-status evidence examples per run"}
	if len(ids) < 2 || len(ids) > 16 {
		return out, ErrBaseline
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		if id < 1 || seen[id] {
			return out, ErrBaseline
		}
		seen[id] = true
	}
	validMetric := false
	for _, value := range latency.Metrics {
		if value == metric {
			validMetric = true
		}
	}
	if !validMetric {
		return out, errors.Join(ErrBaseline, errors.New("choose one WBFT phase metric"))
	}
	rounds := baseline.Summary{From: from, To: to, Runs: []baseline.Run{}, Comparisons: []baseline.Comparison{}}
	networks := map[int64]PhaseComparisonNetwork{}
	hashes := map[[3]string]int64{}
	for _, id := range ids {
		var runNetwork int64
		if err := s.pool.QueryRow(ctx, "SELECT network_id FROM datasets WHERE id=$1", id).Scan(&runNetwork); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return out, ErrBaseline
			}
			return out, err
		}
		if !crossNetwork && runNetwork != network {
			return out, ErrBaseline
		}
		part, err := s.RoundBaseline(ctx, runNetwork, []int64{id}, from, to, node)
		if err != nil {
			return out, err
		}
		identity, err := s.Network(ctx, runNetwork)
		if err != nil {
			return out, err
		}
		networks[id] = PhaseComparisonNetwork{ID: identity.ID, ChainID: identity.ChainID, GenesisHash: identity.GenesisHash, Name: identity.Name}
		for _, input := range part.Runs[0].Inputs {
			key := [3]string{input.Node, input.Profile, input.SHA256}
			if previous, ok := hashes[key]; ok && previous != id {
				return out, errors.Join(ErrBaseline, errors.New("selected runs reuse the same node/profile/source hash"))
			}
			hashes[key] = id
		}
		rounds.Expected = part.Expected
		rounds.Method = part.Method
		rounds.Runs = append(rounds.Runs, part.Runs[0])
	}
	if crossNetwork {
		rounds.Method = "independent network/run observer head claims; local node labels are not matched across networks; no cross-network pooling"
	} else {
		rounds.Comparisons = baseline.Compare(rounds.Runs)
	}
	out.Rounds = rounds
	a, _ := new(big.Int).SetString(from, 10)
	b, _ := new(big.Int).SetString(to, 10)
	for _, run := range rounds.Runs {
		remaining := 100000 - int(out.ContextRecords)
		// Preserve intervening engine/run boundaries even when their own rows have no selected height.
		// Decisions without a view can carry their full height in an explicit number field.
		// Guard its numeric cast inside CASE so malformed metadata cannot fail the request.
		rows, err := s.pool.Query(ctx, `WITH windows AS (
 SELECT input_id,min(line) first_line,max(line) last_line FROM log_events
 WHERE dataset_id=$1 AND ($4='' OR node=$4) AND (
 height BETWEEN $2::numeric AND $3::numeric OR (
 height IS NULL AND kind IN ('NEW_HEAD','FINALIZE_HANDOVER') AND
 CASE WHEN jsonb_typeof(event->'fields'->'number')='string'
 AND event->'fields'->>'number' ~ '^(0|[1-9][0-9]{0,155})$'
 THEN (event->'fields'->>'number')::numeric END BETWEEN $2::numeric AND $3::numeric))
 GROUP BY input_id
 ) SELECT e.event FROM log_events e JOIN windows w ON e.input_id=w.input_id
 WHERE e.dataset_id=$1 AND e.line BETWEEN w.first_line AND w.last_line
 AND e.kind IN ('ROUND_ENTER','PREPREPARE_ACCEPT','QUORUM','FINALIZE_HANDOVER','NEW_HEAD','ENGINE_START','ENGINE_STOP')
 ORDER BY e.input_id,e.line LIMIT $5`, run.Dataset, from, to, node, remaining+1)
		if err != nil {
			return out, err
		}
		records, err := phaseRecords(rows, remaining)
		if err != nil {
			return out, err
		}
		out.ContextRecords += int64(len(records))
		samples := []latency.Sample{}
		observed := map[[2]string]map[string]bool{}
		for _, sample := range latency.Derive(records, latency.Filter{Metric: metric, Node: node}) {
			height, ok := new(big.Int).SetString(sample.Height, 10)
			if !ok || height.Cmp(a) < 0 || height.Cmp(b) > 0 {
				continue
			}
			samples = append(samples, sample)
			key := [2]string{sample.Node, sample.Profile}
			if observed[key] == nil {
				observed[key] = map[string]bool{}
			}
			observed[key][sample.Height] = true
		}
		result := PhaseComparisonRun{Network: networks[run.Dataset], Dataset: run.Dataset, Name: run.Name, Summary: latency.Summarize(samples), Coverage: []PhaseHeightCoverage{}, Examples: []latency.Sample{}}
		// Exclude overall groups, which pool different observers and profiles.
		groups := []latency.Stats{}
		for _, group := range result.Summary.Groups {
			if group.Node != "" {
				groups = append(groups, group)
			}
		}
		result.Summary.Groups = groups
		result.Summary.Method = "nearest_rank; population standard deviation; separate run/node/profile/clock groups; no overall pooling"
		for _, observer := range run.Observers {
			count := int64(len(observed[[2]string{observer.Node, observer.Profile}]))
			result.Coverage = append(result.Coverage, PhaseHeightCoverage{Node: observer.Node, Profile: observer.Profile, Observed: count, Missing: rounds.Expected - count})
		}
		examples := map[[4]string]bool{}
		for _, sample := range samples {
			key := [4]string{sample.Node, sample.Profile, sample.Clock, sample.Status}
			if examples[key] {
				continue
			}
			examples[key] = true
			if len(result.Examples) == 64 {
				result.ExamplesTruncated = true
				continue
			}
			result.Examples = append(result.Examples, sample)
		}
		out.Runs = append(out.Runs, result)
	}
	return out, nil
}
