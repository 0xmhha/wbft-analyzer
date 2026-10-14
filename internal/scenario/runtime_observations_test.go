package scenario

import (
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
