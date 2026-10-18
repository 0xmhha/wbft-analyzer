package statewitness

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

func sourceExample(t *testing.T) (Manifest, *os.Root) {
	t.Helper()
	dir := t.TempDir()
	put := func(name string, raw []byte) FileInput {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		return FileInput{Path: name, SHA256: digest(raw).SHA256}
	}
	address := common.HexToAddress("0x1111")
	empty := crypto.Keccak256Hash([]byte{0x80})
	encoded, err := rlp.EncodeToBytes(stateAccount{Balance: big.NewInt(0), Root: empty, CodeHash: validatorRuntime[:]})
	if err != nil {
		t.Fatal(err)
	}
	root, node := leaf(t, crypto.Keccak256(address[:]), encoded)
	proof := AccountProof{Address: address.Hex(), AccountProof: []string{node}, Balance: "0x0", CodeHash: validatorRuntime.Hex(), Nonce: "0x0", StorageHash: empty.Hex(), StorageProof: []StorageProof{{Key: "0x33", Value: "0x0", Proof: []string{}}}}
	request := []byte(`{"jsonrpc":"2.0","id":9007199254740993,"method":"eth_getProof","params":["` + address.Hex() + `",["0x33"],"0xa"]}`)
	response, err := json.Marshal(proofResponse{JSONRPC: "2.0", ID: json.RawMessage("9007199254740993"), Result: proof})
	if err != nil {
		t.Fatal(err)
	}
	genesis := &types.Header{Number: types.HeightFromUint64(0), Difficulty: big.NewInt(0)}
	genesisRLP, err := codec.EncodeHeader(genesis)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{Number: types.HeightFromUint64(10), Root: root, Difficulty: big.NewInt(0)}
	header.Extra, err = codec.EncodeExtra(&types.WBFTExtra{})
	if err != nil {
		t.Fatal(err)
	}
	headerRLP, err := codec.EncodeBlock(&types.Block{Header: header, Body: types.BodyRaw{rlp.RawValue{0xc0}, rlp.RawValue{0xc0}}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Format: InputFormat, Node: common.HexToAddress("0x01").Hex(), Config: put("config.json", authorityExample("")), Genesis: HeaderInput{Kind: "header_rlp", File: put("genesis.rlp", genesisRLP)}, Points: []PointInput{{Index: "10", Block: HeaderInput{Kind: "block_rlp", File: put("block.rlp", headerRLP)}, Request: put("request.json", request), Response: put("response.json", response)}}}
	opened, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return manifest, opened
}

func encodeManifest(t *testing.T, manifest Manifest) []byte {
	t.Helper()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLoadAuthenticatedWitnessSource(t *testing.T) {
	manifest, root := sourceExample(t)
	bundle, err := Load(context.Background(), encodeManifest(t, manifest), root)
	if err != nil {
		t.Fatal(err)
	}
	out := bundle.Projection()
	if out.ChainID != "7" || len(out.Points) != 1 || out.Points[0].State.Slots != 1 || len(out.Points[0].State.Candidates) != 0 || out.ConfigSHA != manifest.Config.SHA256 {
		t.Fatal("source projection differs", out)
	}
	out.Points[0].State.Contract = "altered"
	if bundle.Projection().Points[0].State.Contract == "altered" {
		t.Fatal("public projection modified the validated bundle")
	}
	raw, _ := json.Marshal(bundle.Projection())
	for _, forbidden := range []string{"path", "accountProof", "params", "canonical_verified", "cause_verified"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("projection contains a source payload or unsupported verdict", forbidden)
		}
	}
}

func TestWitnessSourceRejectsIncompleteOrAmbiguousInputs(t *testing.T) {
	tests := map[string]func(*Manifest, *os.Root){
		"wrong checksum":       func(m *Manifest, _ *os.Root) { m.Points[0].Response.SHA256 = strings.Repeat("0", 64) },
		"missing file":         func(m *Manifest, _ *os.Root) { m.Points[0].Request.Path = "absent.json" },
		"root escape":          func(m *Manifest, _ *os.Root) { m.Config.Path = "../config.json" },
		"absolute path":        func(m *Manifest, _ *os.Root) { m.Config.Path = "/config.json" },
		"wrong encoding":       func(m *Manifest, _ *os.Root) { m.Points[0].Block.Kind = "header_rlp" },
		"full number mismatch": func(m *Manifest, _ *os.Root) { m.Points[0].Index = "11" },
		"number truncation":    func(m *Manifest, _ *os.Root) { m.Points[0].Index = "18446744073709551626" },
		"noncanonical decimal": func(m *Manifest, _ *os.Root) { m.Points[0].Index = "010" },
		"repeated point":       func(m *Manifest, _ *os.Root) { m.Points = append(m.Points, m.Points[0]) },
		"nonzero genesis":      func(m *Manifest, _ *os.Root) { m.Genesis = m.Points[0].Block },
		"no points":            func(m *Manifest, _ *os.Root) { m.Points = nil },
		"symlink": func(m *Manifest, root *os.Root) {
			if err := root.Symlink("config.json", "alias.json"); err != nil {
				t.Fatal(err)
			}
			m.Config.Path = "alias.json"
		},
		"directory": func(m *Manifest, _ *os.Root) { m.Config.Path = "." },
		"late failure": func(m *Manifest, _ *os.Root) {
			second := m.Points[0]
			second.Index = "11"
			m.Points = append(m.Points, second)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest, root := sourceExample(t)
			mutate(&manifest, root)
			bundle, err := Load(context.Background(), encodeManifest(t, manifest), root)
			if err == nil || len(bundle.Projection().Points) != 0 {
				t.Fatal("invalid source produced a trusted prefix", err)
			}
		})
	}
	manifest, root := sourceExample(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx, encodeManifest(t, manifest), root); err == nil {
		t.Fatal("cancelled load succeeded")
	}
	for _, raw := range [][]byte{
		[]byte(strings.Replace(string(encodeManifest(t, manifest)), `"format":`, `"Format":`, 1)),
		append(encodeManifest(t, manifest), []byte(` {}`)...),
		[]byte(strings.Replace(string(encodeManifest(t, manifest)), `"path":"config.json"`, `"path":"config.json","unknown":1`, 1)),
	} {
		if _, err := Load(context.Background(), raw, root); err == nil {
			t.Fatal("unknown or aliased metadata was accepted")
		}
	}
}

func TestRPCRequestBinding(t *testing.T) {
	stateRoot, proof := example(t, false)
	request := `{"jsonrpc":"2.0","id":9007199254740993,"method":"eth_getProof","params":["` + proof.Address + `",["0x1"],"0xa"]}`
	response, _ := json.Marshal(proofResponse{JSONRPC: "2.0", ID: json.RawMessage("9007199254740993"), Result: proof})
	verify := func(req string, res []byte) error {
		_, err := VerifyRPC([]byte(req), res, big.NewInt(10), common.HexToAddress(proof.Address), stateRoot)
		return err
	}
	if err := verify(request, response); err != nil {
		t.Fatal(err)
	}
	for name, altered := range map[string]string{
		"rounded id":      strings.Replace(request, "9007199254740993", "9007199254740992", 1),
		"id domain":       strings.Replace(request, "9007199254740993", `"9007199254740993"`, 1),
		"null id":         strings.Replace(request, "9007199254740993", "null", 1),
		"moving block":    strings.Replace(request, `"0xa"`, `"latest"`, 1),
		"padded block":    strings.Replace(request, `"0xa"`, `"0x0a"`, 1),
		"wrong account":   strings.Replace(request, proof.Address, common.HexToAddress("0x02").Hex(), 1),
		"wrong slot":      strings.Replace(request, `"0x1"`, `"0x2"`, 1),
		"duplicate alias": strings.Replace(request, `["0x1"]`, `["0x1","`+common.HexToHash("0x1").Hex()+`"]`, 1),
		"unknown method":  strings.Replace(request, "eth_getProof", "eth_call", 1),
		"case alias":      strings.Replace(request, `"method":`, `"Method":`, 1),
		"duplicate field": strings.Replace(request, `"method":`, `"method":"eth_getProof","method":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := verify(altered, response); err == nil {
				t.Fatal("mismatched request accepted")
			}
		})
	}
	for _, altered := range []string{
		strings.Replace(string(response), `"result":`, `"error":{"code":-1},"result":`, 1),
		strings.Replace(string(response), `"storageProof":`, `"StorageProof":`, 1),
		strings.Replace(string(response), `"key":`, `"key":"0x2","key":`, 1),
	} {
		if err := verify(request, []byte(altered)); err == nil {
			t.Fatal("invalid response envelope accepted")
		}
	}
}
