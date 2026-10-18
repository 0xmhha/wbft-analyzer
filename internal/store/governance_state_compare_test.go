package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/privacy"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/jackc/pgx/v5"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/statewitness"
)

func TestExecutionKeyClaimsRequireEveryBindingAndExplicitEmptyClaims(t *testing.T) {
	const address = "0x0000000000000000000000000000000000000001"
	base := func() GovernanceStateEvidenceList {
		return GovernanceStateEvidenceList{Index: "10", Evidence: []GovernanceStateEvidence{{Status: "matched", Witness: GovernanceStateWitness{Source: statewitness.Snapshot{ConfigSHA: "one"}}, Point: statewitness.Point{State: statewitness.ValidatorState{WithoutKeys: []string{address}}, Epoch: statewitness.EpochEvidence{Keys: "matched"}}}}}
	}
	for name, tc := range map[string]struct {
		mutate func(*GovernanceStateEvidenceList, *governance.Epoch)
		want   string
	}{
		"legacy nonempty": {func(_ *GovernanceStateEvidenceList, _ *governance.Epoch) {}, "verified_execution_keys"},
		"wrong claim": {func(_ *GovernanceStateEvidenceList, c *governance.Epoch) {
			c.NoKey = []string{}
			c.NoKeyReported = true
		}, "mismatch_execution_keys"},
		"legacy empty": {func(e *GovernanceStateEvidenceList, c *governance.Epoch) {
			e.Evidence[0].Point.State.WithoutKeys = []string{}
			c.NoKey = []string{}
		}, "unverified_execution_keys"},
		"explicit empty": {func(e *GovernanceStateEvidenceList, c *governance.Epoch) {
			e.Evidence[0].Point.State.WithoutKeys = []string{}
			c.NoKey = []string{}
			c.NoKeyReported = true
		}, "verified_execution_keys"},
		"missing header":     {func(e *GovernanceStateEvidenceList, _ *governance.Epoch) { e.Evidence[0].Status = "header_unavailable" }, "unverified_execution_keys"},
		"changed config":     {func(e *GovernanceStateEvidenceList, _ *governance.Epoch) { e.Evidence[0].Status = "config_mismatch" }, "unverified_execution_keys"},
		"epoch key mismatch": {func(e *GovernanceStateEvidenceList, _ *governance.Epoch) { e.Evidence[0].Point.Epoch.Keys = "mismatch" }, "unverified_execution_keys"},
		"genesis":            {func(e *GovernanceStateEvidenceList, _ *governance.Epoch) { e.Index = "0" }, "unverified_execution_keys"},
		"truncated":          {func(e *GovernanceStateEvidenceList, _ *governance.Epoch) { e.Truncated = true }, "ambiguous_execution_keys"},
		"conflicting configs": {func(e *GovernanceStateEvidenceList, _ *governance.Epoch) {
			other := e.Evidence[0]
			other.Witness.Source.ConfigSHA = "two"
			e.Evidence = append(e.Evidence, other)
		}, "ambiguous_execution_keys"},
		"conflicting states": {func(e *GovernanceStateEvidenceList, _ *governance.Epoch) {
			other := e.Evidence[0]
			other.Point.State.WithoutKeys = []string{}
			e.Evidence = append(e.Evidence, other)
		}, "ambiguous_execution_keys"},
		"duplicate corroboration": {func(e *GovernanceStateEvidenceList, _ *governance.Epoch) {
			e.Evidence = append(e.Evidence, e.Evidence[0])
		}, "verified_execution_keys"},
		"stale corroboration": {func(e *GovernanceStateEvidenceList, _ *governance.Epoch) {
			other := e.Evidence[0]
			other.Status = "source_unavailable"
			e.Evidence = append(e.Evidence, other)
		}, "unverified_execution_keys"},
	} {
		t.Run(name, func(t *testing.T) {
			e := base()
			c := governance.Epoch{NoKey: []string{address}}
			tc.mutate(&e, &c)
			out := &GovernanceEpochEvidence{Status: "available", NoKeyStatus: "unverified_execution_keys"}
			applyGovernanceState(out, c, e)
			if out.NoKeyStatus != tc.want {
				t.Fatal(out.NoKeyStatus, tc.want)
			}
		})
	}
}

func TestStateWitnessVisibilityBoundary(t *testing.T) {
	if privacy.Visibility() != "public" {
		t.Skip("public visibility boundary")
	}
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	bundle := witnessStoreExample(t)
	source := bundle.Projection()
	gov := witnessGovernanceDataset(t, s, source, "visibility-source", source.Node)
	meta, _ := json.Marshal(map[string]string{"config_sha256": source.ConfigSHA})
	head, release, e := s.BeginRange(ctx, NetworkKey{ChainID: source.ChainID, GenesisHash: source.GenesisHash}, "visibility-headers", meta)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range source.Points {
		if e = s.PutHeaders(ctx, head.ID, head.NetworkID, []headers.Fact{{Index: p.Index, Number: p.Index, Hash: p.BlockHash, EpochInfo: json.RawMessage("null")}}, []headers.Copy{{Index: p.Index, Hash: p.BlockHash, Node: "header-source"}}, 2); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.FinishRange(ctx, head.ID, 2, ""); e != nil {
		t.Fatal(e)
	}
	release()
	if _, e = s.PutGovernanceStateWitness(ctx, gov.ID, head.ID, bundle); e != nil {
		t.Fatal(e)
	}
	change, _ := json.Marshal(GovernanceChange{Number: "0xa", BlockHash: &source.Points[0].BlockHash})
	if _, e = s.pool.Exec(ctx, `INSERT INTO governance_calls(dataset_id,ordinal,method,call) VALUES($1,5,'wbft_validatorChanges','{}');`, gov.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `INSERT INTO gov_validator_changes(dataset_id,call_ordinal,ordinal,number,row_) VALUES($1,5,1,10,$2)`, gov.ID, change); e != nil {
		t.Fatal(e)
	}

	var info []byte
	var snapshot string
	if e = s.pool.QueryRow(ctx, `SELECT info,snapshot FROM governance_captures WHERE dataset_id=$1`, gov.ID).Scan(&info, &snapshot); e != nil {
		t.Fatal(e)
	}
	var capture GovernanceCapture
	if e = json.Unmarshal(info, &capture); e != nil {
		t.Fatal(e)
	}
	capture.Snapshot = snapshot
	capture.Calls = make([]GovernanceCall, 5)
	for i := range capture.Calls {
		capture.Calls[i] = GovernanceCall{Ordinal: i + 1, Status: "available", Request: governance.Request{Method: "wbft_nodeInfo"}}
	}
	capture.Calls[4].Request.Method = "wbft_validatorChanges"
	info, e = json.Marshal(capture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE governance_captures SET info=$2 WHERE dataset_id=$1`, gov.ID, info); e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET visibility='private' WHERE id=$1`, head.ID); e != nil {
		t.Fatal(e)
	}
	context, e := s.GovernanceHeaderContext(ctx, gov.ID, 5, 1, "changes")
	if e != nil || len(context.Sources) != 0 {
		t.Fatalf("private header-copy source escaped scope: %d %v", len(context.Sources), e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET visibility='public' WHERE id=$1`, head.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET visibility='private' WHERE id=$1`, gov.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.GovernanceStateEvidence(ctx, gov.ID, "10"); !errors.Is(e, ErrNotFound) {
		t.Errorf("direct private proof read: %v", e)
	}
	if _, e = s.GovernanceHeaderContext(ctx, gov.ID, 5, 1, "changes"); !errors.Is(e, ErrNotFound) {
		t.Errorf("private header context should be absent, got %v", e)
	}
	e = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		list, e := governanceStateEvidence(ctx, tx, gov.NetworkID, gov.ID, "10")
		if e == nil && len(list.Evidence) != 0 {
			t.Errorf("private proof escaped internal source filter: %d", len(list.Evidence))
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	reverse, e := s.HeaderGovernanceClaims(ctx, gov.NetworkID, "10")
	if e != nil {
		t.Fatal(e)
	}
	if len(reverse.Claims) != 0 {
		t.Errorf("private source escaped reverse header lookup: %d", len(reverse.Claims))
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET visibility='public' WHERE id=$1`, gov.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE networks SET visibility='private' WHERE id=$1`, gov.NetworkID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.GovernanceStateEvidence(ctx, gov.ID, "10"); !errors.Is(e, ErrNotFound) {
		t.Errorf("private network proof should be absent: %v", e)
	}
	if _, e = s.GovernanceHeaderContext(ctx, gov.ID, 5, 1, "changes"); !errors.Is(e, ErrNotFound) {
		t.Errorf("private network context should be absent: %v", e)
	}
	if _, e = s.HeaderGovernanceClaims(ctx, gov.NetworkID, "10"); !errors.Is(e, ErrNotFound) {
		t.Errorf("private network reverse claims should be absent: %v", e)
	}
}
