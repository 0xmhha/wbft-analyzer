package main

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/triedb"
)

// The exported fixture is created only by tests. It uses the pinned module's
// public synthetic WBFT configuration, never a captured network or source DB.
func TestSyntheticOriginalGenesisReplay(t *testing.T) {
	dir := t.TempDir()
	if selected := os.Getenv("WBFT_EXECUTION_FIXTURE_OUT"); selected != "" {
		if err := os.Mkdir(selected, 0700); err != nil {
			t.Fatal(err)
		}
		dir = selected
	}
	raw, err := json.Marshal(params.TestWBFTChainConfig)
	if err != nil {
		t.Fatal(err)
	}
	var config params.ChainConfig
	if err = json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	config.ChainID = big.NewInt(424242)
	genesis := &core.Genesis{Config: &config, GasLimit: 1000000, Difficulty: big.NewInt(1), Alloc: types.GenesisAlloc{}}
	original, err := json.Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "genesis.json"), original, 0600); err != nil {
		t.Fatal(err)
	}
	db := rawdb.NewMemoryDatabase()
	defer db.Close()
	trie := triedb.NewDatabase(db, triedb.HashDefaults)
	defer trie.Close()
	_, hash, err := core.SetupGenesisBlock(db, trie, genesis)
	if err != nil {
		t.Fatal(err)
	}
	block := rawdb.ReadBlock(db, hash, 0)
	if block == nil {
		t.Fatal("genesis absent")
	}
	encoded, err := rlp.EncodeToBytes(block)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "genesis.rlp"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Format: InputFormat, Node: "0x1111111111111111111111111111111111111111", Genesis: FileInput{Path: "genesis.json", SHA256: digest(original).SHA256}, Blocks: []BlockInput{{Index: "0", File: FileInput{Path: "genesis.rlp", SHA256: digest(encoded).SHA256}}}}
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	report, err := verify(context.Background(), raw, root)
	if err != nil || len(report.Source.Blocks) != 1 || report.Source.GenesisHash != hash.Hex() || len(report.Transactions) != 0 {
		t.Fatal("original synthetic genesis not replayed", err)
	}

	// Uncles are not WBFT execution inputs. A changed body with an unchanged
	// committed header must be rejected even when its supplied checksum matches.
	malformed, err := rlp.EncodeToBytes(block.WithBody(nil, []*types.Header{block.Header()}))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "uncle.rlp"), malformed, 0600); err != nil {
		t.Fatal(err)
	}
	bad := manifest
	bad.Blocks = append([]BlockInput{}, manifest.Blocks...)
	bad.Blocks[0].File = FileInput{Path: "uncle.rlp", SHA256: digest(malformed).SHA256}
	badRaw, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := verify(context.Background(), badRaw, root)
	if err == nil || invalid.Protocol != "" {
		t.Fatal("uncommitted WBFT uncle body accepted")
	}
	// A checksum change at the final source must not emit a completed prefix.
	if err = os.WriteFile(filepath.Join(dir, "genesis.rlp"), append(encoded, 0), 0600); err != nil {
		t.Fatal(err)
	}
	refused, err := verify(context.Background(), raw, root)
	if err == nil || refused.Protocol != "" {
		t.Fatal("changed final source accepted")
	}
	if err = os.WriteFile(filepath.Join(dir, "genesis.rlp"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
}
