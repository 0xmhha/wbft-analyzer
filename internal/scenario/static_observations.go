package scenario

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

type SeedStaticConfigurationObservations struct {
	Source          string                           `json:"source"`
	Configurations  []SeedStaticJournalConfiguration `json:"journal_configurations"`
	UnobservedNodes []int                            `json:"unobserved_nodes"`
}

type SeedStaticJournalConfiguration struct {
	Node          int                      `json:"node"`
	Run           string                   `json:"run"`
	EngineRun     uint64                   `json:"engine_run,string"`
	SHA256        string                   `json:"chain_config_sha256"`
	RulesDigest   string                   `json:"generated_rules_digest"`
	Segments      int                      `json:"journal_segments"`
	Configuration StaticChainConfiguration `json:"configuration"`
}

// Export once per seed so settings, timing and message evidence belong to the
// same execution. Requested settings never stand in for observed journal data.
func simulateConfiguredSeed(ctx context.Context, sc sim.Scenario, retainTiming bool) (*sim.Result, *SeedTimingObservations, *SeedMessageObservations, *SeedStaticConfigurationObservations, error) {
	dir, err := os.MkdirTemp("", "wbft-analyzer-chain-settings-")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	result, runErr := sim.Run(ctx, sc, sim.Output{JournalDir: dir})
	if runErr != nil && !errors.Is(runErr, sim.ErrMessageSelection) {
		return result, nil, nil, nil, runErr
	}
	if result == nil {
		return nil, nil, nil, nil, errors.New("simulator configuration result missing")
	}
	configuration, err := observedStaticConfiguration(ctx, sc, result, dir)
	if err != nil {
		return result, nil, nil, nil, err
	}
	var timing *SeedTimingObservations
	var messages *SeedMessageObservations
	if len(sc.MessageChanges) > 0 {
		messages, err = observedMessages(ctx, sc, result, dir)
	} else if retainTiming {
		timing, err = observedTiming(sc, result, dir)
	}
	if err != nil {
		return result, nil, nil, configuration, err
	}
	return result, timing, messages, configuration, runErr
}

func observedStaticConfiguration(ctx context.Context, sc sim.Scenario, result *sim.Result, directory string) (*SeedStaticConfigurationObservations, error) {
	expected := modeledStaticConfiguration(sc)
	if expected == nil {
		return nil, errors.New("nondefault chain settings required for observations")
	}
	out := &SeedStaticConfigurationObservations{Source: "simulator_journal_chain_configuration/1", Configurations: []SeedStaticJournalConfiguration{}, UnobservedNodes: []int{}}
	for node, validator := range sc.Validators {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(result.Journals[validator.Address()]) == 0 {
			out.UnobservedNodes = append(out.UnobservedNodes, node)
			continue
		}
		dir := filepath.Join(directory, strings.TrimPrefix(strings.ToLower(validator.Address().Hex()), "0x"))
		records, err := journal.ReadAll(nil, dir)
		if err != nil {
			return nil, err
		}
		seen := map[string]int{}
		for _, row := range records {
			segment, ok := row.Body.(*journal.SegmentRec)
			if !ok {
				continue
			}
			if segment.Self != validator.Address() || segment.Run == "" {
				return nil, errors.New("simulator static configuration identity mismatch")
			}
			cfg, err := simulationConfiguration(segment)
			if err != nil {
				return nil, err
			}
			actual := StaticChainConfiguration{RuleActivations: map[string]string{}, AllowedFutureBlockTime: cfg.ConfigAt(types.HeightFromUint64(1)).AllowedFutureBlockTime}
			for name, activation := range cfg.RuleActivations() {
				actual.RuleActivations[string(name)] = activation
			}
			if !maps.Equal(actual.RuleActivations, expected.RuleActivations) || actual.AllowedFutureBlockTime != expected.AllowedFutureBlockTime {
				return nil, errors.New("simulator journal differs from modeled static chain settings")
			}
			digest := sha256.Sum256(segment.Core.ChainConfig)
			hash := hex.EncodeToString(digest[:])
			key := fmt.Sprintf("%s/%d", segment.Run, segment.EngineRun)
			if at, exists := seen[key]; exists {
				if out.Configurations[at].SHA256 != hash {
					return nil, errors.New("simulator static configuration changes within an engine run")
				}
				out.Configurations[at].Segments++
			} else {
				seen[key] = len(out.Configurations)
				out.Configurations = append(out.Configurations, SeedStaticJournalConfiguration{Node: node, Run: segment.Run, EngineRun: segment.EngineRun, SHA256: hash, RulesDigest: cfg.RulesDigest().Hex(), Segments: 1, Configuration: actual})
			}
		}
		if len(seen) == 0 {
			return nil, errors.New("simulator journal lacks static chain configuration")
		}
	}
	return out, nil
}
