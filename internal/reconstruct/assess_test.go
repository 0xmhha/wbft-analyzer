package reconstruct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

const self = "0x1111111111111111111111111111111111111111"
const wideHeight = "18446744073709551617"

func sourceFile(t *testing.T, dir, name string, raw []byte) File {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	return File{Path: path, SHA256: hex.EncodeToString(h[:])}
}

func sourceManifest(t *testing.T, height string, trace bool) Manifest {
	t.Helper()
	row := map[string]any{"t": "2020-01-01T00:00:00Z", "lvl": "info", "msg": "WBFT: start new round", "address": self, "next.seq": height, "next.round": "0", "payload": "PRIVATE_PAYLOAD", "err": "PRIVATE_ERROR"}
	var raw bytes.Buffer
	if err := json.NewEncoder(&raw).Encode(row); err != nil {
		t.Fatal(err)
	}
	if trace {
		row["lvl"], row["msg"], row["current.sequence"], row["current.round"] = "trace", "WBFT: start new ROUND-CHANGE timer", height, "0"
		if err := json.NewEncoder(&raw).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	return Manifest{Format: ManifestFormat, Node: self, Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Log: sourceFile(t, t.TempDir(), "private-source.jsonl", raw.Bytes())}
}

func addFrames(t *testing.T, m *Manifest, height string, peer bool) {
	t.Helper()
	n, _ := new(big.Int).SetString(height, 10)
	message := &codec.Message{Code: codec.CodePrepare, View: types.View{Sequence: types.MustHeightFromBig(n)}, Digest: types.Hash{1}}
	// A deterministic public fixture scalar, never an operational key.
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	key, err := ecdsa.PrivateKeyFromBytes(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := codec.SigningPayload(message, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	message.Signature, err = ecdsa.SignData(sign, key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.EncodeMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(payload)
	sum := hex.EncodeToString(hash[:])
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "payloads", sum[:2]), 0700); err != nil {
		t.Fatal(err)
	}
	sourceFile(t, filepath.Join(dir, "payloads", sum[:2]), sum, payload)
	var raw bytes.Buffer
	raw.WriteByte('\n')
	for i := 0; i < 6; i++ {
		row := map[string]any{"v": 1, "type": "frame", "node": self, "run": "synthetic", "seq": uint64(9007199254740993 + i), "t_wall": "2020-01-01T00:00:00Z", "t_mono_ns": i, "dir": "in", "code": "0x13", "size": len(payload), "payload_sha256": sum}
		if peer {
			row["peer"] = "0x2222222222222222222222222222222222222222"
		}
		if err := json.NewEncoder(&raw).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	sourceFile(t, dir, "frames-synthetic.jsonl", raw.Bytes())
	input := messages.Input{ID: "frames", Kind: "frames", Node: self, Path: dir}
	fingerprint, err := messages.Fingerprint(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	m.Frames = &File{Path: dir, SHA256: fingerprint.SHA256}
}

func TestReconstructionInfoAndEmptyHeightsCannotBecomeComplete(t *testing.T) {
	m := sourceManifest(t, wideHeight, false)
	result, err := Assess(context.Background(), m, wideHeight, "18446744073709551619")
	if err != nil || len(result.Heights) != 3 || result.CoreExecuted {
		t.Fatal(result, err)
	}
	for _, height := range result.Heights {
		if height.Status != "not_possible" || !contains(height.Issues, "timer_source_unavailable") || !contains(height.Issues, "received_message_source_unavailable") {
			t.Fatal(height)
		}
	}
	raw, _ := json.Marshal(result)
	for _, private := range []string{m.Log.Path, "PRIVATE_PAYLOAD", "PRIVATE_ERROR", "private-source.jsonl"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("local path or arbitrary input escaped into assessment")
		}
	}
	if result.Heights[0].Height != wideHeight || count(result.Heights[0], "log_event") != 1 {
		t.Fatal(result.Heights[0])
	}
}

func TestReconstructionTraceAndReceivedBytesRemainPartialWithExactSources(t *testing.T) {
	m := sourceManifest(t, wideHeight, true)
	addFrames(t, &m, wideHeight, true)
	fixture, err := os.ReadFile("../source/runtimeobs/testdata/config-history-synthetic.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	runtime := sourceFile(t, t.TempDir(), "runtime-private.jsonl", fixture)
	m.Runtime = &runtime
	result, err := Assess(context.Background(), m, wideHeight, wideHeight)
	if err != nil || result.CoreExecuted || len(result.Heights) != 1 {
		t.Fatal(result, err)
	}
	h := result.Heights[0]
	if !contains(h.Issues, "source_run_association_unbound") || result.Sources.LogProfile != "gstable@740526d03" || len(result.Sources.LogProfileSHA) != 64 || result.Sources.LogNormalizer == "" || result.Sources.FrameNormalizer == "" || result.Sources.RuntimeNormalizer == "" {
		t.Fatal("projection versions or unresolved process association were lost", result.Sources, h)
	}
	if h.Status != "partial" || count(h, "received_frame") != 6 || count(h, "timer_arm_log") != 1 || count(h, "startup_config_candidate") != 1 || !contains(h.Issues, "processing_order_unbound") || !contains(h.Issues, "application_answers_unbound") {
		t.Fatal(h)
	}
	for _, e := range h.Evidence {
		if e.Kind == "received_frame" && (len(e.Examples) != 4 || e.Examples[0].Line != 2 || e.Examples[0].Sequence != "9007199254740993" || e.Examples[0].File != "frames-synthetic.jsonl") {
			t.Fatal(e)
		}
	}
}

func TestReconstructionUnknownPeerDoesNotSupplyReceivedIdentity(t *testing.T) {
	m := sourceManifest(t, "1", true)
	addFrames(t, &m, "1", false)
	result, err := Assess(context.Background(), m, "1", "1")
	if err != nil || result.Heights[0].Status != "not_possible" || count(result.Heights[0], "received_frame_unknown_peer") != 6 {
		t.Fatal(result, err)
	}
}

func TestReconstructionRefusesChangedAndCrossNodeSourcesAtomically(t *testing.T) {
	for _, change := range []string{"log_hash", "frame_node", "payload_bytes", "runtime_node", "log_node"} {
		t.Run(change, func(t *testing.T) {
			m := sourceManifest(t, "1", true)
			addFrames(t, &m, "1", true)
			switch change {
			case "log_hash":
				m.Log.SHA256 = strings.Repeat("f", 64)
			case "frame_node":
				path := filepath.Join(m.Frames.Path, "frames-synthetic.jsonl")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				sourceFile(t, m.Frames.Path, "frames-synthetic.jsonl", bytes.ReplaceAll(raw, []byte(self), []byte("0x3333333333333333333333333333333333333333")))
			case "payload_bytes":
				paths, err := filepath.Glob(filepath.Join(m.Frames.Path, "payloads", "*", "*"))
				if err != nil || len(paths) != 1 {
					t.Fatal(paths, err)
				}
				if err := os.WriteFile(paths[0], []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "runtime_node":
				raw, err := os.ReadFile("../source/runtimeobs/testdata/config-history-synthetic.jsonl")
				if err != nil {
					t.Fatal(err)
				}
				file := sourceFile(t, t.TempDir(), "runtime.jsonl", bytes.ReplaceAll(raw, []byte(self), []byte("0x3333333333333333333333333333333333333333")))
				m.Runtime = &file
			case "log_node":
				raw := []byte(`{"t":"2020-01-01T00:00:00Z","lvl":"info","msg":"WBFT: start","address":"0x3333333333333333333333333333333333333333"}` + "\n")
				m.Log = sourceFile(t, t.TempDir(), "log.jsonl", raw)
			}
			if change == "frame_node" || change == "payload_bytes" {
				// Even a newly pinned directory cannot bless internally inconsistent bytes.
				fingerprint, err := messages.Fingerprint(context.Background(), messages.Input{ID: "frames", Kind: "frames", Node: self, Path: m.Frames.Path})
				if err != nil {
					t.Fatal(err)
				}
				m.Frames.SHA256 = fingerprint.SHA256
			}
			result, err := Assess(context.Background(), m, "1", "1")
			if err == nil || result.Version != "" || result.Heights != nil {
				t.Fatal("invalid source emitted a partial assessment", result, err)
			}
		})
	}
}

func TestReconstructionCanonicalChainIsVerifiedNotAssumed(t *testing.T) {
	m := sourceManifest(t, "1", false)
	genesis := &types.Block{Header: &types.Header{Number: types.HeightFromUint64(0), Difficulty: big.NewInt(1)}, Body: types.BodyRaw{{0xc0}, {0xc0}}}
	child := &types.Block{Header: &types.Header{Number: types.HeightFromUint64(1), ParentHash: codec.BlockHash(genesis.Header), Difficulty: big.NewInt(1)}, Body: types.BodyRaw{{0xc0}, {0xc0}}}
	m.Network.GenesisHash = strings.ToLower(codec.BlockHash(genesis.Header).Hex())
	raw, err := sim.EncodeChain([]*types.Block{genesis, child})
	if err != nil {
		t.Fatal(err)
	}
	chain := sourceFile(t, t.TempDir(), "chain.rlp", raw)
	m.Chain = &chain
	result, err := Assess(context.Background(), m, "1", "2")
	if err != nil || count(result.Heights[0], "canonical_block") != 1 || count(result.Heights[1], "canonical_block") != 0 || result.Heights[0].Status != "not_possible" {
		t.Fatal(result, err)
	}
	child.Header.ParentHash = types.Hash{9}
	raw, err = sim.EncodeChain([]*types.Block{genesis, child})
	if err != nil {
		t.Fatal(err)
	}
	chain = sourceFile(t, t.TempDir(), "chain.rlp", raw)
	m.Chain = &chain
	if _, err := Assess(context.Background(), m, "1", "2"); err == nil {
		t.Fatal("broken canonical parents accepted")
	}
}

func TestReconstructionManifestAndRangeRefusals(t *testing.T) {
	m := sourceManifest(t, "1", false)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(raw, []byte(` {}`)...), bytes.Replace(raw, []byte(`"node":`), []byte(`"node":"`+self+`","node":`), 1), bytes.Replace(raw, []byte(`"format":`), []byte(`"unknown":true,"format":`), 1)} {
		path := sourceFile(t, t.TempDir(), "manifest.json", bad).Path
		if _, err := LoadManifest(context.Background(), path); err == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
	for _, pair := range [][2]string{{"0", "1"}, {"01", "2"}, {"-1", "1"}, {"2", "1"}, {"1", "10001"}, {"1", new(big.Int).Lsh(big.NewInt(1), 256).String()}} {
		if _, err := Assess(context.Background(), m, pair[0], pair[1]); err == nil {
			t.Fatal("invalid or oversized range accepted", pair)
		}
	}
	link := filepath.Join(t.TempDir(), "log.jsonl")
	if err := os.Symlink(m.Log.Path, link); err != nil {
		t.Fatal(err)
	}
	m.Log.Path = link
	if _, err := Assess(context.Background(), m, "1", "1"); err == nil {
		t.Fatal("symlink source accepted")
	}
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
