package ingest

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// testStore owns a fresh schema and drops it in t.Cleanup. The source is a new
// unsigned header; no existing dataset or original input is rewritten.
func TestDomainSigningMarkerDoesNotReuseLegacyDataset(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	dir := t.TempDir()
	node := types.Address{1}
	writer, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Run: "marker-model", Self: node, ChainID: big.NewInt(7)})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	network := logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}
	manifest := messages.Manifest{Format: messages.Format, Name: "marker-model", Network: network, Clock: messages.Clock{Model: "unknown"}, Inputs: []messages.Input{{ID: "model", Kind: "journal", Node: strings.ToLower(node.Hex()), Path: dir}}}
	_, metadata, err := messages.Prepare(ctx, manifest)
	if err != nil {
		t.Fatal(err)
	}
	var old map[string]json.RawMessage
	if err := json.Unmarshal(metadata, &old); err != nil {
		t.Fatal(err)
	}
	delete(old, "signing_normalizer")
	oldMetadata, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	key := store.NetworkKey{ChainID: network.ChainID, GenesisHash: network.GenesisHash}
	prior, release, err := s.BeginMessages(ctx, key, manifest.Name, oldMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRange(ctx, prior.ID, 0, ""); err != nil {
		release()
		t.Fatal(err)
	}
	release()
	if result, err := Messages(ctx, s, manifest); err == nil || result.Skipped {
		t.Fatal("old signing projection was reused", result, err)
	}
	// The rejected reimport must leave the old metadata usable under its old key.
	same, release, err := s.BeginMessages(ctx, key, manifest.Name, oldMetadata)
	if err != nil {
		t.Fatal("old dataset metadata changed", err)
	}
	if same.ID != prior.ID {
		release()
		t.Fatal("old dataset replaced")
	}
	if err := s.FinishRange(ctx, same.ID, 0, ""); err != nil {
		release()
		t.Fatal(err)
	}
	release()
	manifest.Name = "marker-model-new"
	fresh, err := Messages(ctx, s, manifest)
	if err != nil || fresh.Skipped || fresh.DatasetID == prior.ID {
		t.Fatal(fresh, err)
	}
	again, err := Messages(ctx, s, manifest)
	if err != nil || !again.Skipped || again.DatasetID != fresh.DatasetID {
		t.Fatal("same new marker is not idempotent", again, err)
	}
}
