package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/privacy"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/statewitness"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

func witnessStoreExample(t *testing.T) statewitness.Bundle {
	t.Helper()
	dir := t.TempDir()
	put := func(name string, raw []byte) statewitness.FileInput {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		return statewitness.FileInput{Path: name, SHA256: hex.EncodeToString(sum[:])}
	}
	address := common.HexToAddress("0x1111")
	empty := crypto.Keccak256Hash([]byte{0x80})
	code := common.HexToHash("0xb5ce66a9f8c1a08247521c60191f8b11e31e472d8dc26ea163e66de307303dac")
	account, err := rlp.EncodeToBytes(struct {
		Nonce    uint64
		Balance  *big.Int
		Root     common.Hash
		CodeHash []byte
	}{0, big.NewInt(0), empty, code[:]})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := rlp.EncodeToBytes([][]byte{append([]byte{0x20}, crypto.Keccak256(address[:])...), account})
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := crypto.Keccak256Hash(leaf)
	proof := statewitness.AccountProof{Address: address.Hex(), AccountProof: []string{"0x" + hex.EncodeToString(leaf)}, Balance: "0x0", Nonce: "0x0", CodeHash: code.Hex(), StorageHash: empty.Hex(), StorageProof: []statewitness.StorageProof{{Key: "0x33", Value: "0x0", Proof: []string{}}}}
	response, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": proof})
	if err != nil {
		t.Fatal(err)
	}
	responseFile := put("response.json", response)
	genesis, err := codec.EncodeHeader(&types.Header{Difficulty: big.NewInt(0)})
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"chainId":7,"anzeon":{"wbft":{},"systemContracts":{"govValidator":{"address":"` + address.Hex() + `","version":"v1"}}}}`)
	manifest := statewitness.Manifest{Format: statewitness.InputFormat, Node: common.HexToAddress("0x01").Hex(), Config: put("config.json", config), Genesis: statewitness.HeaderInput{Kind: "header_rlp", File: put("genesis.rlp", genesis)}, Points: []statewitness.PointInput{}}
	for _, index := range []uint64{10, 20} {
		extra, err := codec.EncodeExtra(&types.WBFTExtra{})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := codec.EncodeHeader(&types.Header{Number: types.HeightFromUint64(index), Difficulty: big.NewInt(0), Root: stateRoot, Extra: extra})
		if err != nil {
			t.Fatal(err)
		}
		decimal := strconv.FormatUint(index, 10)
		request := []byte(`{"jsonrpc":"2.0","id":1,"method":"eth_getProof","params":["` + address.Hex() + `",["0x33"],"0x` + strconv.FormatUint(index, 16) + `"]}`)
		manifest.Points = append(manifest.Points, statewitness.PointInput{Index: decimal, Block: statewitness.HeaderInput{Kind: "header_rlp", File: put("header-"+decimal+".rlp", raw)}, Request: put("request-"+decimal+".json", request), Response: responseFile})
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	bundle, err := statewitness.Load(context.Background(), raw, root)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func witnessGovernanceDataset(t *testing.T, s *Store, source statewitness.Snapshot, name, node string) Dataset {
	t.Helper()
	ctx := context.Background()
	d, release, err := s.BeginGovernance(ctx, NetworkKey{ChainID: source.ChainID, GenesisHash: source.GenesisHash}, name, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	identity := governance.Identity{Address: node, ChainID: source.ChainID, GenesisHash: source.GenesisHash, Head: "25"}
	capture := GovernanceCapture{DatasetID: d.ID, Normalizer: governance.Normalizer, From: "0x0", To: "0x19", Before: identity, After: identity, Calls: []GovernanceCall{}}
	raw, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, `INSERT INTO governance_captures(dataset_id,node,snapshot,info) VALUES($1,$2,$3,$4)`, d.ID, node, strings.Repeat("a", 64), raw); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishRange(ctx, d.ID, 0, ""); err != nil {
		t.Fatal(err)
	}
	release()
	return d
}

func TestGovernanceStateWitnessCanonicalOwnershipAndInvalidation(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	bundle := witnessStoreExample(t)
	source := bundle.Projection()
	gov := witnessGovernanceDataset(t, s, source, "witness-governance", source.Node)
	other := witnessGovernanceDataset(t, s, source, "other-governance", common.HexToAddress("0x02").Hex())
	meta, _ := json.Marshal(map[string]string{"config_sha256": source.ConfigSHA})
	head, release, err := s.BeginRange(ctx, NetworkKey{ChainID: source.ChainID, GenesisHash: source.GenesisHash}, "witness-headers", meta)
	if err != nil {
		t.Fatal(err)
	}
	putPoint := func(point statewitness.Point) {
		t.Helper()
		fact := headers.Fact{Index: point.Index, Number: point.Index, Hash: point.BlockHash, EpochInfo: json.RawMessage("null")}
		copy := headers.Copy{Index: point.Index, Hash: point.BlockHash, Node: "header-source"}
		if err := s.PutHeaders(ctx, head.ID, head.NetworkID, []headers.Fact{fact}, []headers.Copy{copy}, 1); err != nil {
			t.Fatal(err)
		}
	}
	putPoint(source.Points[0])
	if err = s.FinishRange(ctx, head.ID, 1, ""); err != nil {
		t.Fatal(err)
	}
	release()
	if _, err = s.PutGovernanceStateWitness(ctx, gov.ID, head.ID, bundle); !errors.Is(err, ErrStateWitnessBinding) {
		t.Fatal("last point without canonical source accepted", err)
	}
	var count int
	if err = s.pool.QueryRow(ctx, `SELECT count(*) FROM governance_state_witnesses`).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial attachment remained", count, err)
	}
	putPoint(source.Points[1])
	if err = s.FinishRange(ctx, head.ID, 2, ""); err != nil {
		t.Fatal(err)
	}
	var saved GovernanceStateWitness
	for range 2 {
		saved, err = s.PutGovernanceStateWitness(ctx, gov.ID, head.ID, bundle)
		if err != nil {
			t.Fatal(err)
		}
	}
	if saved.Points != 2 || len(saved.Source.Points) != 0 {
		t.Fatal("parent retained point payloads", saved)
	}
	if _, err = s.PutGovernanceStateWitness(ctx, other.ID, head.ID, bundle); !errors.Is(err, ErrStateWitnessBinding) {
		t.Fatal("wrong source node accepted", err)
	}
	if _, err = s.PutGovernanceStateWitness(ctx, gov.ID, head.ID, statewitness.Bundle{}); !errors.Is(err, ErrStateWitnessBinding) {
		t.Fatal("zero bundle accepted", err)
	}
	evidence, err := s.GovernanceStateEvidence(ctx, gov.ID, "10")
	if err != nil || len(evidence.Evidence) != 1 || evidence.Evidence[0].Status != "matched" {
		t.Fatal(evidence, err)
	}
	elsewhere, err := s.GovernanceStateEvidence(ctx, other.ID, "10")
	if err != nil || len(elsewhere.Evidence) != 0 {
		t.Fatal("cross-dataset witness leaked", elsewhere, err)
	}
	for _, test := range []struct {
		query       string
		args        []any
		status      string
		restore     string
		restoreArgs []any
	}{
		{`UPDATE datasets SET metadata='{}' WHERE id=$1`, []any{head.ID}, "config_mismatch", `UPDATE datasets SET metadata=$2 WHERE id=$1`, []any{head.ID, meta}},
		{`UPDATE datasets SET status='failed' WHERE id=$1`, []any{head.ID}, "source_unavailable", `UPDATE datasets SET status='complete' WHERE id=$1`, []any{head.ID}},
		{`UPDATE heights SET fact=jsonb_set(fact,'{number}','"18446744073709551626"') WHERE network_id=$1 AND index_=10`, []any{head.NetworkID}, "header_mismatch", `UPDATE heights SET fact=jsonb_set(fact,'{number}','"10"') WHERE network_id=$1 AND index_=10`, []any{head.NetworkID}},
		{`UPDATE networks SET chain_id='8' WHERE id=$1`, []any{head.NetworkID}, "network_mismatch", `UPDATE networks SET chain_id='7' WHERE id=$1`, []any{head.NetworkID}},
	} {
		if _, err = s.pool.Exec(ctx, test.query, test.args...); err != nil {
			t.Fatal(err)
		}
		got, err := s.GovernanceStateEvidence(ctx, gov.ID, "10")
		if err != nil || len(got.Evidence) != 1 || got.Evidence[0].Status != test.status {
			t.Fatal(test.status, got, err)
		}
		if _, err = s.pool.Exec(ctx, test.restore, test.restoreArgs...); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "export")
	m, err := s.ExportDataset(ctx, gov.Name, out, "public")
	if err != nil {
		t.Fatal(err)
	}
	assertBundleDigests(t, out, m)
	if len(m.Datasets) != 2 {
		t.Fatal("bound header dependency not exported", m.Datasets)
	}
	for name, want := range map[string]int{"governance_state_witnesses": 1, "governance_state_points": 2} {
		raw, err := os.ReadFile(filepath.Join(out, name+".jsonl"))
		if err != nil || strings.Count(string(raw), "\n") != want {
			t.Fatal(name, string(raw), err)
		}
	}
	if privacy.Visibility() == "public" {
		if _, err = s.pool.Exec(ctx, `UPDATE datasets SET visibility='private' WHERE id=$1`, head.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = s.ExportDataset(ctx, gov.Name, filepath.Join(t.TempDir(), "refused"), "public"); !errors.Is(err, ErrExportPrivate) {
			t.Fatal("private dependency exported", err)
		}
		if _, err = s.pool.Exec(ctx, `UPDATE datasets SET visibility='public' WHERE id=$1`, head.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.DeleteDataset(ctx, head.NetworkID, head.ID, head.Name); err != nil {
		t.Fatal(err)
	}
	stale, err := s.GovernanceStateEvidence(ctx, gov.ID, "10")
	if err != nil || len(stale.Evidence) != 1 || stale.Evidence[0].Status != "source_unavailable" || stale.Evidence[0].Witness.HeadersDataset != nil {
		t.Fatal("deleted source left a verified binding", stale, err)
	}
	deletedExport, err := s.ExportDataset(ctx, gov.Name, filepath.Join(t.TempDir(), "without-headers"), "public")
	if err != nil || len(deletedExport.Datasets) != 1 {
		t.Fatal(deletedExport, err)
	}
	if _, err = s.DeleteDataset(ctx, gov.NetworkID, gov.ID, gov.Name); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"governance_state_witnesses", "governance_state_points"} {
		if err = s.pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("ownership cascade", table, count, err)
		}
	}
}
