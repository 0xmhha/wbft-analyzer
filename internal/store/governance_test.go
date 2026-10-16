package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
)

func governanceFixture(t *testing.T) (governance.Archive, string) {
	t.Helper()
	a, sha, err := governance.Load("../source/governance/testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	return a, sha
}

func TestGovernancePersistenceExactScopesExportAndCascade(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, sha := governanceFixture(t)
	snap, err := governance.Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginGovernance(ctx, NetworkKey{ChainID: snap.Before.ChainID, GenesisHash: snap.Before.GenesisHash}, "governance", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	info, err := s.PutGovernance(ctx, d.ID, "archive", sha, a)
	if err != nil {
		t.Fatal(err)
	}
	if info.Atomic || info.Operations == nil || *info.Operations != 1 || info.Gaps == nil || *info.Gaps != 2 || info.Before.Head != "18446744073709551616" {
		t.Fatal(info)
	}
	if _, err = s.PutGovernance(ctx, d.ID, "archive", sha, a); err != nil {
		t.Fatal("idempotence", err)
	}
	for table, want := range map[string]int{"governance_captures": 1, "governance_calls": 9, "gov_ops": 3, "gov_gaps": 2, "gov_states": 1, "gov_proposals": 1, "gov_validator_changes": 1} {
		var count int
		if err = s.pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE dataset_id=$1`, d.ID).Scan(&count); err != nil || count != want {
			t.Fatal(table, count, err)
		}
	}
	var number, proposal string
	if err = s.pool.QueryRow(ctx, `SELECT number::text FROM gov_ops WHERE dataset_id=$1 AND call_ordinal=3`, d.ID).Scan(&number); err != nil || number != "18446744073709551615" {
		t.Fatal(number, err)
	}
	if err = s.pool.QueryRow(ctx, `SELECT proposal_id::text FROM gov_proposals WHERE dataset_id=$1`, d.ID).Scan(&proposal); err != nil || proposal != number {
		t.Fatal(proposal, err)
	}
	var known, unknown int
	if err = s.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE gap_from=0 AND gap_to=0),count(*) FILTER(WHERE gap_from IS NULL AND gap_to IS NULL) FROM gov_gaps WHERE dataset_id=$1`, d.ID).Scan(&known, &unknown); err != nil || known != 1 || unknown != 1 {
		t.Fatal(known, unknown, err)
	}
	call, err := s.GovernanceCall(ctx, d.ID, 7)
	var history governance.ProposalHistory
	decodeErr := json.Unmarshal(call.Data, &history)
	if err != nil || decodeErr != nil || call.Request.Scope != "proposal-full-history-current-state" || len(history.Ops) != 1 || history.Ops[0].Number != "0x1" {
		t.Fatal(call, err)
	}
	if _, err = s.PutGovernance(ctx, d.ID, "rpc", sha, a); err == nil {
		t.Fatal("source overwrite accepted")
	}
	if _, err = s.GovernanceCall(ctx, d.ID, 99); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	release()
	out := filepath.Join(t.TempDir(), "export")
	m, err := s.ExportDataset(ctx, d.Name, out, "public")
	if err != nil {
		t.Fatal(err)
	}
	assertBundleDigests(t, out, m)
	if len(m.Objects) != 0 || len(m.Datasets) != 1 {
		t.Fatal("unexpected export closure", m)
	}
	for _, table := range []string{"governance_captures", "governance_calls", "gov_ops", "gov_gaps", "gov_states", "gov_proposals", "gov_validator_changes"} {
		raw, err := os.ReadFile(filepath.Join(out, table+".jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{"synthetic-sensitive-data", hex.EncodeToString([]byte("synthetic-sensitive-data"))} {
			if strings.Contains(string(raw), marker) {
				t.Fatal("opaque source leaked", table)
			}
		}
	}
	if _, err = s.pool.Exec(ctx, `DELETE FROM datasets WHERE id=$1`, d.ID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM gov_ops)+(SELECT count(*) FROM governance_calls)+(SELECT count(*) FROM gov_gaps)+(SELECT count(*) FROM gov_states)+(SELECT count(*) FROM gov_proposals)+(SELECT count(*) FROM gov_validator_changes)`).Scan(&count); err != nil || count != 0 {
		t.Fatal("cascade", count, err)
	}
}

func TestGovernanceTransactionRollbackAndForeignIdentity(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, sha := governanceFixture(t)
	snap, err := governance.Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginGovernance(ctx, NetworkKey{ChainID: snap.Before.ChainID, GenesisHash: snap.Before.GenesisHash}, "rollback-governance", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// Fail after the capture and preceding batches have been queued.
	if _, err = s.pool.Exec(ctx, `CREATE FUNCTION reject_governance() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$; CREATE TRIGGER reject_governance BEFORE INSERT ON gov_proposals FOR EACH ROW EXECUTE FUNCTION reject_governance()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PutGovernance(ctx, d.ID, "archive", sha, a); err == nil {
		t.Fatal("injected failure absent")
	}
	var count, progress int
	var status string
	if err = s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM governance_captures),progress,status FROM datasets WHERE id=$1`, d.ID).Scan(&count, &progress, &status); err != nil || count != 0 || progress != 0 || status != "importing" {
		t.Fatal("partial commit", count, progress, status, err)
	}
	if _, err = s.pool.Exec(ctx, `DROP TRIGGER reject_governance ON gov_proposals`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PutGovernance(ctx, d.ID, "archive", sha, a); err != nil {
		t.Fatal("retry", err)
	}
	foreign, unlock, err := s.BeginGovernance(ctx, NetworkKey{ChainID: "9", GenesisHash: snap.Before.GenesisHash}, "foreign-governance", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err = s.PutGovernance(ctx, foreign.ID, "archive", sha, a); err == nil {
		t.Fatal("foreign network accepted")
	}
}

func TestGovernanceUnavailableAndEmptyCounts(t *testing.T) {
	a, sha := governanceFixture(t)
	for _, unavailable := range []bool{false, true} {
		if unavailable {
			a.Replies[2].Response = json.RawMessage(`{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"synthetic-sensitive-data"}}`)
		} else {
			a.Replies[2].Response = json.RawMessage(`{"jsonrpc":"2.0","id":3,"result":[]}`)
		}
		snap, err := governance.Normalize(a)
		if err != nil {
			t.Fatal(err)
		}
		info, err := GovernanceInfo(1, "archive", sha, snap)
		if err != nil || unavailable && info.Operations != nil || !unavailable && (info.Operations == nil || *info.Operations != 0) {
			t.Fatal(info, err)
		}
	}
}
