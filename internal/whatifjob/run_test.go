package whatifjob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/jackc/pgx/v5"
)

func TestRunUsesRetainedBytesAndPreservesVerifiedExperiment(t *testing.T) {
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
	if _, err = rand.Read(token); err != nil {
		t.Fatal(err)
	}
	schema := "t_whatif_" + hex.EncodeToString(token)
	if _, err = conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
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
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	s, err := store.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	validators := make([]sim.Validator, 4)
	for i := range validators {
		validators[i], err = sim.NewValidator(keccak.Sum256Bytes([]byte("synthetic-whatif-run-" + strconv.Itoa(i))))
		if err != nil {
			t.Fatal(err)
		}
	}
	var links []sim.Link
	for i, a := range validators {
		for j, b := range validators {
			if i != j {
				links = append(links, sim.Link{From: a.Address(), To: b.Address(), Delay: []time.Duration{10 * time.Millisecond}})
			}
		}
	}
	journalRoot := t.TempDir()
	simulation, err := sim.Run(ctx, sim.Scenario{Name: "synthetic-whatif-run", Seed: 4, Validators: validators, Links: links, Until: sim.Stop{Height: 3, Duration: time.Minute}}, sim.Output{JournalDir: journalRoot})
	if err != nil || len(simulation.Violations) != 0 {
		t.Fatal(err, simulation.Violations)
	}
	for node, files := range simulation.Journals {
		dir := t.TempDir()
		for name, raw := range files {
			if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		input := messages.Input{ID: "journal", Kind: "journal", Node: strings.ToLower(node.Hex()), Path: dir}
		summary, err := messages.Fingerprint(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		storage := t.TempDir()
		if err = os.Chmod(storage, 0700); err != nil {
			t.Fatal(err)
		}
		archived, err := messages.Archive(ctx, storage, []messages.Prepared{{Input: input, Summary: summary}})
		if err != nil {
			t.Fatal(err)
		}
		dataset, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "8282", GenesisHash: codec.BlockHash(simulation.Chain[0].Header).Hex()}, "synthetic-timer-experiment", json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		release()
		if err = s.PutMessageInput(ctx, dataset.ID, summary); err != nil {
			t.Fatal(err)
		}
		if err = s.PutInputFiles(ctx, dataset.ID, summary.ID, archived[summary.ID]); err != nil {
			t.Fatal(err)
		}
		seconds := "2"
		result, err := Run(ctx, s, Options{Dataset: dataset.ID, Input: summary.ID, Chain: filepath.Join(journalRoot, "chain.rlp"), Policy: whatif.Policy{Request: &seconds}})
		if err != nil || result.ID == 0 || result.Summary.Status != "completed" || !result.Summary.TimerValidated || result.Summary.Steps == 0 {
			t.Fatal(result, err)
		}
		rows, err := s.WhatifResults(ctx, result.ID, 0, 1000)
		if err != nil || len(rows) == 0 {
			t.Fatal(rows, err)
		}
		for _, step := range rows {
			if step.Generated && step.Source != nil {
				t.Fatal("generated source ordinal fabricated")
			}
		}
		return
	}
	t.Fatal("no source journal")
}
