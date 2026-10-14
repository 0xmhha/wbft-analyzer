package scenario

import (
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
	"github.com/0xmhha/wbft/types"
)

func runtimeFixture(t *testing.T) RuntimeObservation {
	t.Helper()
	path := "../source/runtimeobs/testdata/synthetic.jsonl"
	c, e := runtimeobs.Load(path)
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	in, e := InspectRuntimeObservation(Input{ID: "runtime", Kind: "runtime", Node: c.Node, SHA256: c.SourceSHA}, f)
	if e != nil {
		t.Fatal(e)
	}
	return in
}
func TestRuntimeStartupScalarBindingRetainsUnprovedExecution(t *testing.T) {
	in := runtimeFixture(t)
	policy := uint64(0)
	cfg := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 1, BlockPeriodSeconds: 1, EpochLength: 10, AllowedFutureBlockTime: 2, ProposerPolicy: &policy}, nil, types.GenesisInit{}, nil)
	got, e := BindRuntimeObservation(in, cfg, []string{in.Source.Node})
	if e != nil || got.Configuration != "startup_scalars_verified" || got.Startup.Line != 1 || got.Startup.Config.Height != "18446744073709551616" || got.ExecutionModelComplete || got.CallCount != 1 {
		t.Fatal(got, e)
	}
	other := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 10, AllowedFutureBlockTime: 2, ProposerPolicy: &policy}, nil, types.GenesisInit{}, nil)
	got, e = BindRuntimeObservation(in, other, []string{in.Source.Node})
	if e != nil || got.Configuration != "mismatch" {
		t.Fatal(got, e)
	}
	if _, e = BindRuntimeObservation(in, cfg, []string{"other"}); e == nil {
		t.Fatal("foreign node accepted")
	}
	bad := in
	bad.Source.SHA256 = strings.Repeat("a", 64)
	if _, e = BindRuntimeObservation(bad, cfg, []string{in.Source.Node}); e == nil {
		t.Fatal("changed source accepted")
	}
	in.Capture.Points[0].Config.Transitions = "1"
	got, e = BindRuntimeObservation(in, cfg, []string{in.Source.Node})
	if e != nil || len(got.Unavailable) != 1 || got.Unavailable[0] != "later_configuration_unproved" || got.ExecutionModelComplete {
		t.Fatal(got, e)
	}
}

func TestRuntimeEngineBindingDoesNotPromoteExecutionModel(t *testing.T) {
	c, e := runtimeobs.Load("../source/runtimeobs/testdata/core-synthetic.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	in := RuntimeObservation{Source: Input{ID: "engine", Kind: "runtime", Node: c.Node, SHA256: c.SourceSHA}, Capture: c}
	policy := uint64(0)
	cfg := types.NewConfig(types.WBFTParams{RequestTimeoutSeconds: 1, BlockPeriodSeconds: 1, EpochLength: 10, AllowedFutureBlockTime: 2, ProposerPolicy: &policy}, nil, types.GenesisInit{}, nil)
	got, e := BindRuntimeObservation(in, cfg, []string{c.Node})
	if e != nil || got.EngineStates["observed_stopped"] != 1 || got.ExecutionModelComplete || got.TaskStates["observed_result"] != 1 {
		t.Fatal(got, e)
	}
}

func TestEveryStartupConfigurationIsComparedAtItsOwnFullHeight(t *testing.T) {
	c, e := runtimeobs.Load("../source/runtimeobs/testdata/config-history-synthetic.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	in := RuntimeObservation{Source: Input{ID: "history", Kind: "runtime", Node: c.Node, SHA256: c.SourceSHA}, Capture: c}
	h, ok := new(big.Int).SetString("18446744073709551617", 10)
	if !ok {
		t.Fatal("height")
	}
	policy := uint64(0)
	base := types.WBFTParams{RequestTimeoutSeconds: 1, BlockPeriodSeconds: 1, EpochLength: 10, AllowedFutureBlockTime: 2, ProposerPolicy: &policy}
	cfg := types.NewConfig(base, []types.Transition{{Block: h, WBFT: &types.WBFTParams{RequestTimeoutSeconds: 2}}}, types.GenesisInit{}, nil)
	got, e := BindRuntimeObservation(in, cfg, []string{c.Node})
	if e != nil || got.Configuration != "startup_scalars_verified" || len(got.Configurations) != 2 || len(got.Startups) != 2 || got.Configurations[1].Point.Config.Height != h.String() || got.ExecutionModelComplete {
		t.Fatal(got, e)
	}
	bad := types.NewConfig(base, nil, types.GenesisInit{}, nil)
	got, e = BindRuntimeObservation(in, bad, []string{c.Node})
	if e != nil || got.Configuration != "mismatch" || got.Configurations[0].Comparison != "startup_scalars_verified" || got.Configurations[1].Comparison != "mismatch" {
		t.Fatal("second snapshot skipped", got, e)
	}
	in.Capture.Engines[1].Configs = append(in.Capture.Engines[1].Configs, in.Capture.Engines[1].Configs[0])
	in.Capture.Engines[1].Configuration = "ambiguous"
	got, e = BindRuntimeObservation(in, cfg, []string{c.Node})
	if e != nil || got.Configuration == "startup_scalars_verified" || len(got.Configurations) != 3 {
		t.Fatal("duplicate chosen", got, e)
	}
	in.Capture.Engines = nil
	got, e = BindRuntimeObservation(in, cfg, []string{c.Node})
	if e != nil || got.Configuration != "unbound_startup_candidates" || len(got.Startups) != 2 {
		t.Fatal("first unbound startup chosen", got, e)
	}
}
