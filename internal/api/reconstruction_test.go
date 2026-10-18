package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/reconstruct"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestReconstructionAtomicStorageScopeAndCoordinates(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	node := "0x" + strings.Repeat("1", 40)
	genesis := "0x" + strings.Repeat("0", 64)
	d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: "7", GenesisHash: genesis}, "synthetic-reconstruction", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	in := logs.InputSummary{ID: "log", Node: node, Profile: "synthetic", ProfileSHA256: strings.Repeat("b", 64), SHA256: strings.Repeat("a", 64), Bytes: 100}
	if err = s.PutLogInput(ctx, d.ID, in); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, d.ID, 100, ""); err != nil {
		t.Fatal(err)
	}
	release()
	result := reconstruct.ExecutionResult{
		Assessment:       reconstruct.Assessment{Version: reconstruct.Version, Phase: "reconstructed_execution", Node: node, ChainID: "7", GenesisHash: genesis, From: "18446744073709551617", To: "18446744073709551617", CoreExecuted: true, Sources: reconstruct.Sources{ProcessingScopes: []reconstruct.ProcessingScope{}, LogSHA: in.SHA256, LogBytes: in.Bytes, LogProfile: in.Profile, LogProfileSHA: in.ProfileSHA256}, Heights: []reconstruct.Height{{Height: "18446744073709551617", Status: "complete", Issues: []string{}, Evidence: []reconstruct.Evidence{}}}},
		ExecutionVersion: reconstruct.ExecutionVersion, ComparisonModel: reconstruct.ComparisonModel, CoreVersion: strings.Repeat("c", 40), AllImprovementsOff: true,
		Executions: []reconstruct.HeightExecution{{Height: "18446744073709551617", Run: "log:1", Status: "complete", Issues: []string{}, Steps: []reconstruct.ExecutionStep{}, Differences: 1}},
	}
	for i := 0; i < 3; i++ {
		step := reconstruct.ExecutionStep{CoreApplied: true, Issues: []string{}, Input: reconstruct.ReconstructedInput{Ordinal: fmt.Sprint(i + 1), ObservationInstance: "2", Kind: "message", Via: "direct", Height: result.From, Round: "9007199254740993", Source: reconstruct.Point{Kind: "processing_boundary", File: "input_observations", Line: int64(10 + i), Sequence: fmt.Sprint(40 + i)}}, Observed: []reconstruct.Projection{}, Computed: []reconstruct.Projection{}, Differences: []reconstruct.DifferenceCandidate{}}
		if i == 1 {
			step.Differences = append(step.Differences, reconstruct.DifferenceCandidate{Kind: "timer_arm"})
		}
		result.Executions[0].Steps = append(result.Executions[0].Steps, step)
	}
	id, err := s.PutReconstruction(ctx, d.ID, "log", result)
	if err != nil {
		t.Fatal(err)
	}
	if again, e := s.PutReconstruction(ctx, d.ID, "log", result); e != nil || again != id {
		t.Fatal("duplicate result changed", again, e)
	}
	bad := result
	bad.Sources.LogSHA = strings.Repeat("e", 64)
	if _, e := s.PutReconstruction(ctx, d.ID, "log", bad); !errors.Is(e, store.ErrReconstructionSource) {
		t.Fatal("wrong log accepted", e)
	}
	bad = result
	bad.ChainID = "8"
	if _, e := s.PutReconstruction(ctx, d.ID, "log", bad); !errors.Is(e, store.ErrReconstructionSource) {
		t.Fatal("wrong network accepted", e)
	}
	// A later invalid row must roll back the run and all preceding steps.
	bad = result
	bad.Executions = append([]reconstruct.HeightExecution{}, result.Executions...)
	bad.Executions = append(bad.Executions, reconstruct.HeightExecution{Height: "invalid", Run: "log:1", Steps: result.Executions[0].Steps})
	if _, e := s.PutReconstruction(ctx, d.ID, "log", bad); e == nil {
		t.Fatal("invalid step accepted")
	}
	c := client{t, (&Server{Store: s}).Handler()}
	base := fmt.Sprintf("/v1/networks/%d/datasets/%d/reconstruction", d.NetworkID, d.ID)
	var list ReconstructionList
	if c.do("GET", base, nil, &list) != 200 || len(list.Runs) != 1 || list.Runs[0].Steps != 3 || list.Runs[0].Complete != 1 || list.Runs[0].Differences != 1 {
		t.Fatal(list)
	}
	var detail store.ReconstructionDetail
	if c.do("GET", fmt.Sprintf("%s/%d", base, id), nil, &detail) != 200 || len(detail.Summary.Executions[0].Steps) != 0 || detail.From != result.From {
		t.Fatal(detail)
	}
	path := fmt.Sprintf("%s/%d/steps", base, id)
	var page ReconstructionPage
	if c.do("GET", path+"?limit=1", nil, &page) != 200 || len(page.Steps) != 1 || page.Next == nil || *page.Next != 1 || page.Steps[0].Step.Input.Source.Sequence != "40" || page.Steps[0].Step.Input.Ordinal != "1" || page.Steps[0].Step.Input.Round != "9007199254740993" {
		t.Fatal(page)
	}
	if c.do("GET", path+"?after=1&different=true&height="+result.From+"&run=log:1", nil, &page) != 200 || len(page.Steps) != 1 || page.Steps[0].Position != 2 || page.Next != nil {
		t.Fatal(page)
	}
	for _, suffix := range []string{"?limit=101", "?after=-1", "?height=NaN", "?different=maybe", "?different=", "?run=a%2Fb", "?after=1&after=2", "?unknown=1"} {
		if c.do("GET", path+suffix, nil, nil) != 400 {
			t.Fatal(suffix)
		}
	}
	if c.do("GET", fmt.Sprintf("/v1/networks/999/datasets/%d/reconstruction/%d", d.ID, id), nil, nil) != 404 {
		t.Fatal("cross-network result exposed")
	}
	data, _ := json.Marshal(detail)
	for _, forbidden := range []string{`"path"`, `"payload"`, `"engine_run"`, `"journal_step"`} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("invented native identity or source bytes", forbidden)
		}
	}
	other, unlock, err := s.BeginRun(ctx, store.NetworkKey{ChainID: "7", GenesisHash: genesis}, "synthetic-reconstruction-other", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PutLogInput(ctx, other.ID, in); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, other.ID, 100, ""); err != nil {
		t.Fatal(err)
	}
	unlock()
	if _, err = s.PutReconstruction(ctx, other.ID, "log", result); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "reconstruction-export")
	manifest, err := s.ExportDataset(ctx, d.Name, out, "private")
	if err != nil || len(manifest.Datasets) != 1 || manifest.Datasets[0] != d.ID {
		t.Fatal(manifest, err)
	}
	for _, table := range []struct {
		name string
		rows int
	}{{"reconstruction_runs", 1}, {"reconstruction_steps", 3}} {
		raw, err := os.ReadFile(filepath.Join(out, table.name+".jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
		if len(lines) != table.rows {
			t.Fatal("export included another dataset or lost rows", table.name, len(lines))
		}
		for _, line := range lines {
			var row map[string]json.RawMessage
			if err := json.Unmarshal(line, &row); err != nil {
				t.Fatal(err)
			}
			field, want := "run_id", id
			if table.name == "reconstruction_runs" {
				field, want = "dataset_id", d.ID
			}
			if string(row[field]) != fmt.Sprint(want) {
				t.Fatal("cross-dataset reconstruction export", table.name, field)
			}
		}
	}
}
