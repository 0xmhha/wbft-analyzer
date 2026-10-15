package scenariojob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
	"github.com/jackc/pgx/v5"
)

func TestStoredNetworkExperimentPreservesCancelledSeedPrefix(t *testing.T) {
	dsn := os.Getenv("WBFT_ANALYZER_TEST_DSN")
	if dsn == "" {
		t.Skip("WBFT_ANALYZER_TEST_DSN is not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	token := make([]byte, 8)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	schema := "t_scenario_" + hex.EncodeToString(token)
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := conn.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	q.Set("search_path", schema)
	parsed.RawQuery = q.Encode()
	s, err := store.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-scenario", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	keys, err := scenario.TestValidators([]types.Address{{19: 1}, {19: 2}, {19: 3}, {19: 4}})
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Scenario: sim.Scenario{Validators: keys, Until: sim.Stop{Height: 3, Duration: time.Minute}}, Provenance: scenario.Provenance{ModelSHA256: strings.Repeat("e", 64), Dataset: d.ID, Version: scenario.FitVersion, Inputs: []scenario.Input{{ID: "synthetic", Kind: "journal", Node: "a", SHA256: strings.Repeat("a", 64)}}, ChainSHA256: strings.Repeat("b", 64), CoreCommit: strings.Repeat("c", 40), Seeds: []int64{1, 2}}, Model: scenario.Assessment{Version: scenario.FitVersion, Status: "partial", Issues: []scenario.Issue{{Code: "synthetic"}}}, Recorded: []scenario.RoundCount{{Total: 100}}, Change: scenario.NetworkChange{Kind: "cut_outgoing", Node: new(int), ToNS: int64(time.Minute)}, From: 1, To: 3}
	future := uint64(3)
	o.Scenario.Params.RuleActivations = map[types.RuleName]string{types.RejectNumberJump: "18446744073709551616"}
	o.Scenario.Params.AllowedFutureBlockTime = &future
	running, cancel := context.WithCancel(ctx)
	o.OnSeedStored = func(scenario.SeedRecord) error { cancel(); return nil }
	result, err := run(running, s, o)
	if err == nil || result.ID < 1 || result.Summary.Status != "partial" {
		t.Fatalf("cancel %+v %v", result, err)
	}
	rows, err := s.ScenarioSeeds(ctx, d.ID, result.ID, "baseline", 0, 10)
	if err != nil || len(rows) != 1 || rows[0].Result.Seed != 1 {
		t.Fatal("saved seed prefix lost", err)
	}
	if rows[0].Result.Execution == nil || rows[0].Result.Execution.StaticConfiguration == nil || len(rows[0].Result.Execution.StaticConfiguration.Configurations) != 4 {
		t.Fatal("saved partial prefix lost actual chain settings", rows[0].Result)
	}
	other, err := s.ScenarioSeeds(ctx, d.ID, result.ID, "counterfactual", 0, 10)
	if err != nil || len(other) != 0 {
		t.Fatal("invented counterfactual suffix", err)
	}
	o.OnSeedStored = nil
	result, err = run(ctx, s, o)
	if err != nil || result.Summary.Status != "completed" || result.Summary.Credibility() != "model_incomplete" {
		t.Fatalf("complete %+v %v", result, err)
	}
	stored, err := s.ScenarioRun(ctx, d.ID, result.ID)
	if err != nil || stored.StaticConfiguration == nil || stored.StaticConfiguration.RuleActivations[string(types.RejectNumberJump)] != "18446744073709551616" || stored.StaticConfiguration.AllowedFutureBlockTime != future {
		t.Fatal("stored experiment lost modeled settings", stored, err)
	}
}

func TestPublicRunRefusesUnprovedCoreBeforeStorage(t *testing.T) {
	result, err := Run(context.Background(), nil, Options{Provenance: scenario.Provenance{CoreCommit: strings.Repeat("0", 40)}})
	if err == nil || result.ID != 0 {
		t.Fatal("wrong core identity reached storage")
	}
}
