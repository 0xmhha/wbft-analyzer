package scenario

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
	"github.com/0xmhha/wbft/types"
)

func TestEmpiricalParametersKeepContractExecutionSeparate(t *testing.T) {
	raw, err := os.ReadFile("../source/runtimeobs/testdata/synthetic.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for _, transitions := range []string{"0", "1"} {
		lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
		for i, line := range lines {
			var row map[string]json.RawMessage
			if err := json.Unmarshal(line, &row); err != nil {
				t.Fatal(err)
			}
			if config, ok := row["config"]; ok {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(config, &fields); err != nil {
					t.Fatal(err)
				}
				fields["SystemContractUpgrades"] = json.RawMessage("2")
				fields["Transitions"] = json.RawMessage(transitions)
				row["config"], err = json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
			}
			lines[i], err = json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
		}
		data := append(bytes.Join(lines, []byte("\n")), '\n')
		capture, err := runtimeobs.FromReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		in := RuntimeObservation{Source: Input{ID: "runtime", Kind: "runtime", Node: capture.Node, SHA256: capture.SourceSHA}, Capture: capture}
		policy := uint64(0)
		params := types.WBFTParams{RequestTimeoutSeconds: 1, BlockPeriodSeconds: 1, EpochLength: 10, AllowedFutureBlockTime: 2, ProposerPolicy: &policy}
		cfg := types.NewConfig(params, nil, types.GenesisInit{}, nil)
		bound, err := BindRuntimeObservation(in, cfg, []string{capture.Node})
		if err != nil {
			t.Fatal(err)
		}
		if bound.Configuration != "startup_scalars_verified" || len(bound.Unavailable) != 1 || bound.Unavailable[0] != "later_configuration_unproved" || bound.ExecutionModelComplete {
			t.Fatal(bound)
		}
		if empiricalParametersVerified(bound) != (transitions == "0") {
			t.Fatal("scalar schedule and contract execution were conflated", bound)
		}
		if transitions == "0" {
			testEmpiricalParameterHistory(t, bound)
		}
		params.RequestTimeoutSeconds = 2
		mismatch, err := BindRuntimeObservation(in, types.NewConfig(params, nil, types.GenesisInit{}, nil), []string{capture.Node})
		if err != nil || empiricalParametersVerified(mismatch) {
			t.Fatal("mismatched WBFT scalar accepted", mismatch, err)
		}
		bound.CaptureComplete = false
		if empiricalParametersVerified(bound) {
			t.Fatal("incomplete source promoted")
		}
	}
}

func testEmpiricalParameterHistory(t *testing.T, bound RuntimeBinding) {
	t.Helper()
	point := bound.Startups[0]
	for _, tc := range []struct {
		name   string
		change func(*RuntimeBinding)
	}{
		{"unknown_gap", func(b *RuntimeBinding) { b.Unavailable = append([]string{"unknown_gap"}, b.Unavailable...) }},
		{"ambiguous_state", func(b *RuntimeBinding) { b.Configurations[1].State = "ambiguous" }},
		{"later_mismatch", func(b *RuntimeBinding) { b.Configurations[1].Comparison = "mismatch" }},
		{"later_transition", func(b *RuntimeBinding) { b.Configurations[1].Point.Config.Transitions = "1" }},
		{"later_scalar_change", func(b *RuntimeBinding) { b.Configurations[1].Point.Config.RequestTimeoutMS = "2000" }},
		{"wrong_node", func(b *RuntimeBinding) {
			b.Configurations[1].Point.Config.Address = "0x0000000000000000000000000000000000000002"
		}},
		{"missing_config", func(b *RuntimeBinding) { b.Configurations[1].Point.Config = nil }},
		{"malformed_upgrade_count", func(b *RuntimeBinding) { b.Configurations[1].Point.Config.SystemContractUpgrades = "02" }},
		{"overflow_upgrade_count", func(b *RuntimeBinding) {
			b.Configurations[1].Point.Config.SystemContractUpgrades = "18446744073709551616"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bound
			c1, c2 := *point.Config, *point.Config
			p1, p2 := point, point
			p1.Config, p2.Config = &c1, &c2
			b.Configurations = []RuntimeConfiguration{
				{State: "observed", Comparison: "startup_scalars_verified", Point: p1},
				{State: "observed", Comparison: "startup_scalars_verified", Point: p2},
			}
			if !empiricalParametersVerified(b) {
				t.Fatal("equal historical snapshots refused")
			}
			tc.change(&b)
			if empiricalParametersVerified(b) {
				t.Fatal("unproved historical scalar schedule accepted", b)
			}
		})
	}
	b := bound
	b.Configurations = nil
	b.Startups = []runtimeobs.Point{point, point}
	if empiricalParametersVerified(b) {
		t.Fatal("unbound multiple startup candidates accepted")
	}
}
