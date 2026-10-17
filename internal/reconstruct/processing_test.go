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
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

type processingFixture struct {
	m            Manifest
	rows, frames []map[string]any
	self, peer   string
	payload      []byte
}

func processingWall(second int) string {
	return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(second) * time.Second).Format(time.RFC3339Nano)
}
func signedFixtureMessage(t *testing.T, code codec.Code, scalar byte, height string, digest byte) ([]byte, string) {
	t.Helper()
	keyBytes := make([]byte, 32)
	keyBytes[31] = scalar
	key, err := ecdsa.PrivateKeyFromBytes(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	n, ok := new(big.Int).SetString(height, 10)
	if !ok {
		t.Fatal(height)
	}
	m := &codec.Message{Code: code, View: types.View{Sequence: types.MustHeightFromBig(n)}, Digest: types.Hash{digest}}
	if code == codec.CodePreprepare {
		m.Proposal = &types.Block{Header: &types.Header{Number: types.MustHeightFromBig(n), Time: 1}, Body: types.BodyRaw{{0xc0}, {0xc0}}}
	}
	raw, err := codec.SigningPayload(m, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature, err = ecdsa.SignData(raw, key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.EncodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	return payload, strings.ToLower(ecdsa.Address(key).Hex())
}
func newProcessingFixture(t *testing.T, height string) *processingFixture {
	t.Helper()
	pp, node := signedFixtureMessage(t, codec.CodePreprepare, 1, height, 1)
	own, _ := signedFixtureMessage(t, codec.CodePrepare, 1, height, 1)
	incoming, peer := signedFixtureMessage(t, codec.CodePrepare, 2, height, 1)
	log := func(second int, level, phrase string) map[string]any {
		return map[string]any{"t": processingWall(second), "lvl": level, "msg": phrase, "address": node}
	}
	round := log(1, "info", "WBFT: start new round")
	round["next.seq"], round["next.round"], round["next.proposer"] = height, "0", node
	timer := log(2, "trace", "WBFT: start new ROUND-CHANGE timer")
	timer["current.sequence"], timer["current.round"] = height, "0"
	payload := log(4, "trace", "WBFT: PRE-PREPARE payload")
	payload["payload"] = "0x" + hex.EncodeToString(pp)
	vote := log(6, "trace", "WBFT: PREPARE payload")
	vote["payload"] = "0x" + hex.EncodeToString(own)
	handle := log(10, "debug", "WBFT: handle PRE-PREPARE message")
	accepted := log(11, "debug", "WBFT: accepted PRE-PREPARE message")
	prepare := log(12, "debug", "WBFT: handle PREPARE message")
	prepare["current.sequence"], prepare["current.round"] = height, "0"
	prepare["msg.sequence"], prepare["msg.round"], prepare["msg.code"], prepare["msg.source"] = height, "0", 19, peer
	frames := []map[string]any{}
	frame := func(second int, dir, code string, payload []byte) {
		sum := sha256.Sum256(payload)
		frames = append(frames, map[string]any{"v": 1, "type": "frame", "node": node, "run": "synthetic-process", "t_wall": processingWall(second), "t_mono_ns": second * 1000000000, "dir": dir, "peer": peer, "code": code, "size": len(payload), "payload_sha256": hex.EncodeToString(sum[:]), "test_payload": payload})
	}
	frame(5, "out", "0x12", pp)
	frame(7, "out", "0x13", own)
	frame(8, "in", "0x13", incoming)
	return &processingFixture{m: Manifest{Format: ManifestFormat, Node: node, Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Scopes: []RunScope{{LogRun: "log:0", FrameRun: "synthetic-process", From: processingWall(0), To: processingWall(20)}}}, rows: []map[string]any{round, timer, payload, vote, handle, accepted, prepare}, frames: frames, self: node, peer: peer, payload: incoming}
}
func copyFields(x map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range x {
		out[k] = v
	}
	return out
}
func (f *processingFixture) write(t *testing.T) Manifest {
	t.Helper()
	var data bytes.Buffer
	for _, row := range f.rows {
		if err := json.NewEncoder(&data).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	m := f.m
	m.Log = sourceFile(t, t.TempDir(), "local-private-log.jsonl", data.Bytes())
	dir := t.TempDir()
	data.Reset()
	for i, original := range f.frames {
		row := copyFields(original)
		payload := row["test_payload"].([]byte)
		delete(row, "test_payload")
		sum := sha256.Sum256(payload)
		hash := hex.EncodeToString(sum[:])
		row["payload_sha256"], row["size"], row["seq"] = hash, len(payload), uint64(9007199254740993)+uint64(i)
		p := filepath.Join(dir, "payloads", hash[:2])
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
		sourceFile(t, p, hash, payload)
		if err := json.NewEncoder(&data).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	sourceFile(t, dir, "frames-synthetic.jsonl", data.Bytes())
	sum, err := messages.Fingerprint(context.Background(), messages.Input{Kind: "frames", Node: m.Node, Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	m.Frames = &File{Path: dir, SHA256: sum.SHA256}
	f.m = m
	return m
}
func assessProcessing(t *testing.T, f *processingFixture, height string) Assessment {
	t.Helper()
	out, err := Assess(context.Background(), f.write(t), height, height)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestProcessingLinksExplicitScopeAndPositiveVerificationSources(t *testing.T) {
	f := newProcessingFixture(t, wideHeight)
	out := assessProcessing(t, f, wideHeight)
	if out.CoreExecuted || out.Heights[0].Status != "partial" || !contains(out.Heights[0].Issues, "core_inputs_not_reconstructed") {
		t.Fatal(out)
	}
	if out.Sources.ProcessingVersion != ProcessingVersion || len(out.Sources.ProcessingScopes) != 1 || out.Sources.ProcessingScopes[0].Status != "declared_content_anchored" || out.Sources.ProcessingScopes[0].DistinctPayloads != 2 {
		t.Fatal(out.Sources)
	}
	rows := out.Heights[0].Processing
	if len(rows) != 2 {
		t.Fatal(rows)
	}
	if rows[0].Status != "linked" || rows[0].ApplicationVerification != "success_witness" || rows[0].Accepted == nil || rows[0].Handler.Line != 5 || rows[0].Accepted.Line != 6 || !rows[0].Handler.ViewInferred || rows[0].Candidates[0].Source.Line != 3 || rows[0].Candidates[0].Peer != f.self || rows[0].CoreInputReady {
		t.Fatal(rows[0])
	}
	if rows[1].Status != "linked" || rows[1].Candidates[0].Source.Sequence != "9007199254740995" || rows[1].Candidates[0].Peer != f.peer || rows[1].Height != wideHeight {
		t.Fatal(rows[1])
	}
	raw, _ := json.Marshal(out)
	for _, secret := range []string{"local-private-log.jsonl", f.m.Log.Path, hex.EncodeToString(f.payload), "PRIVATE_ERROR"} {
		if secret != "" && bytes.Contains(raw, []byte(secret)) {
			t.Fatal("private source escaped into metadata")
		}
	}
}
func TestProcessingNeverGuessesMissingAmbiguousOrLaterEvidence(t *testing.T) {
	tests := []struct {
		name, phase, status, verification string
		change                            func(*processingFixture)
	}{
		{"missing acceptance", "PRE-PREPARE", "linked", "unavailable", func(f *processingFixture) { f.rows = append(f.rows[:5], f.rows[6:]...) }},
		{"duplicate acceptance", "PRE-PREPARE", "linked", "ambiguous", func(f *processingFixture) {
			row := copyFields(f.rows[5])
			f.rows = append(f.rows[:6], append([]map[string]any{row}, f.rows[6:]...)...)
		}},
		{"duplicate frame bytes", "PREPARE", "ambiguous", "not_applicable", func(f *processingFixture) {
			x := copyFields(f.frames[2])
			x["t_wall"], x["t_mono_ns"] = processingWall(9), 9000000000
			f.frames = append(f.frames, x)
		}},
		{"conflicting frame bytes", "PREPARE", "ambiguous", "not_applicable", func(f *processingFixture) {
			x := copyFields(f.frames[2])
			payload, _ := signedFixtureMessage(t, codec.CodePrepare, 2, "1", 2)
			x["test_payload"], x["t_wall"], x["t_mono_ns"] = payload, processingWall(9), 9000000000
			f.frames = append(f.frames, x)
		}},
		{"duplicate own payload", "PRE-PREPARE", "ambiguous", "unbound_acceptance", func(f *processingFixture) {
			row := copyFields(f.rows[2])
			row["t"] = processingWall(9)
			f.rows = append(f.rows[:4], append([]map[string]any{row}, f.rows[4:]...)...)
		}},
		{"frame after handler", "PREPARE", "missing", "not_applicable", func(f *processingFixture) {
			f.frames[2]["t_wall"], f.frames[2]["t_mono_ns"] = processingWall(13), 13000000000
		}},
		{"equal wall is not processing order", "PREPARE", "missing", "not_applicable", func(f *processingFixture) {
			f.frames[2]["t_wall"], f.frames[2]["t_mono_ns"] = processingWall(12), 12000000000
		}},
		{"no scope declaration", "PRE-PREPARE", "unbound_scope", "unbound_acceptance", func(f *processingFixture) { f.m.Scopes = nil }},
		{"outside scope", "PRE-PREPARE", "outside_scope", "unbound_acceptance", func(f *processingFixture) { f.m.Scopes[0].To = processingWall(9) }},
		{"one distinct content anchor", "PRE-PREPARE", "unbound_scope", "unbound_acceptance", func(f *processingFixture) {
			f.frames[1]["test_payload"] = f.frames[0]["test_payload"]
			f.frames[1]["code"] = "0x12"
		}},
		{"declared hash mismatch", "PREPARE", "missing", "not_applicable", func(f *processingFixture) { f.rows[6]["digest"] = "0x" + strings.Repeat("f", 64) }},
		{"acceptance outside scope", "PRE-PREPARE", "linked", "unbound_acceptance", func(f *processingFixture) { f.m.Scopes[0].To = processingWall(10) }},
		{"wrong handler code", "PREPARE", "invalid_context", "not_applicable", func(f *processingFixture) { f.rows[6]["msg.code"] = 20 }},
		{"missing handler peer", "PREPARE", "invalid_context", "not_applicable", func(f *processingFixture) { delete(f.rows[6], "msg.source") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newProcessingFixture(t, "1")
			tc.change(f)
			out := assessProcessing(t, f, "1")
			found := false
			for _, row := range out.Heights[0].Processing {
				if row.Phase == tc.phase {
					found = true
					if row.Status != tc.status || row.ApplicationVerification != tc.verification || row.CoreInputReady {
						t.Fatalf("%+v", row)
					}
				}
			}
			if !found {
				t.Fatal("handler disappeared")
			}
			if out.CoreExecuted || out.Heights[0].Status == "complete" {
				t.Fatal(out)
			}
		})
	}
}
func TestProcessingRepeatedSourceDoesNotCreateIndependentDeliveries(t *testing.T) {
	f := newProcessingFixture(t, "1")
	x := copyFields(f.rows[6])
	x["t"] = processingWall(13)
	f.rows = append(f.rows, x)
	out := assessProcessing(t, f, "1")
	for _, row := range out.Heights[0].Processing {
		if row.Phase == "PREPARE" && (row.Status != "reused_source" || row.SourceUses != 2) {
			t.Fatal(row)
		}
	}
}
func TestProcessingInfoOnlyStillCannotReconstructAnyHeight(t *testing.T) {
	f := newProcessingFixture(t, "1")
	rows := []map[string]any{}
	for _, r := range f.rows {
		if r["lvl"] == "info" {
			rows = append(rows, r)
		}
	}
	f.rows = rows
	out, err := Assess(context.Background(), f.write(t), "1", "3")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range out.Heights {
		if h.Status != "not_possible" || len(h.Processing) != 0 {
			t.Fatal(h)
		}
	}
}
func TestProcessingRefusesInvalidScopesAndForeignProcessingNode(t *testing.T) {
	for _, kind := range []string{"missing frames", "duplicate scope", "unknown run", "long scope", "foreign node"} {
		t.Run(kind, func(t *testing.T) {
			f := newProcessingFixture(t, "1")
			m := f.write(t)
			switch kind {
			case "missing frames":
				m.Frames = nil
			case "duplicate scope":
				m.Scopes = append(m.Scopes, m.Scopes[0])
			case "unknown run":
				m.Scopes[0].FrameRun = "unknown"
			case "long scope":
				m.Scopes[0].To = "2020-01-03T00:00:00Z"
			case "foreign node":
				f.rows[5]["address"] = f.peer
				m = f.write(t)
			}
			out, err := Assess(context.Background(), m, "1", "1")
			if err == nil || out.Version != "" || len(out.Heights) != 0 {
				t.Fatal("invalid source produced assessment", out, err)
			}
		})
	}
}

func TestProcessingRoundChangeWithoutDigestRemainsOneCandidate(t *testing.T) {
	f := newProcessingFixture(t, "1")
	payload, _ := signedFixtureMessage(t, codec.CodeRoundChange, 2, "1", 0)
	f.frames[2]["test_payload"], f.frames[2]["code"] = payload, "0x15"
	f.rows[6]["msg"], f.rows[6]["lvl"], f.rows[6]["msg.code"] = "WBFT: handle ROUND-CHANGE message", "info", 21
	out := assessProcessing(t, f, "1")
	row := out.Heights[0].Processing[1]
	if row.CandidateCount != 1 || row.Status != "linked" || row.Phase != "ROUND-CHANGE" {
		t.Fatal(row)
	}
}
func TestProcessingReportsFullAmbiguousCountWithBoundedExamples(t *testing.T) {
	f := newProcessingFixture(t, "1")
	for i := 0; i < 5; i++ {
		x := copyFields(f.frames[2])
		x["t_wall"], x["t_mono_ns"] = processingWall(9), 9000000000
		f.frames = append(f.frames, x)
	}
	out := assessProcessing(t, f, "1")
	row := out.Heights[0].Processing[1]
	if row.CandidateCount != 6 || row.Status != "ambiguous" || !row.CandidatesTruncated || len(row.Candidates) != 4 {
		t.Fatal(row)
	}
}
func TestProcessingScopeCannotOverlapAnotherEngineInOneFrameRun(t *testing.T) {
	f := newProcessingFixture(t, "1")
	m := f.write(t)
	other := m.Scopes[0]
	other.LogRun = "log:1"
	m.Scopes = append(m.Scopes, other)
	if _, err := Assess(context.Background(), m, "1", "1"); err == nil {
		t.Fatal("overlapping engine scopes accepted")
	}
}
func TestProcessingRequiresMessageViewInsteadOfCurrentEngineHeight(t *testing.T) {
	f := newProcessingFixture(t, "2")
	f.rows[6]["current.sequence"] = "1"
	out, err := Assess(context.Background(), f.write(t), "1", "2")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Heights[0].Processing) != 0 || len(out.Heights[1].Processing) != 2 || out.Heights[1].Processing[1].Height != "2" {
		t.Fatal(out.Heights)
	}
}

func TestProcessingInterveningInputsBreakAcceptance(t *testing.T) {
	for _, tc := range []struct{ name, phrase, level string }{
		{"proposal request", "WBFT: handle block proposal request", "debug"},
		{"round timeout", "WBFT: TIMER CHANGING ROUND", "warn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProcessingFixture(t, "1")
			row := map[string]any{"t": processingWall(10), "lvl": tc.level, "msg": tc.phrase, "address": f.self, "current.sequence": "1", "current.round": "0"}
			rows := append([]map[string]any{}, f.rows[:5]...)
			rows = append(rows, row)
			rows = append(rows, f.rows[5:]...)
			f.rows = rows
			out := assessProcessing(t, f, "1")
			found := false
			for _, w := range out.Heights[0].Processing {
				if w.Phase == "PRE-PREPARE" {
					found = true
					if w.ApplicationVerification != "unavailable" || w.Accepted != nil {
						t.Fatal("intervening input did not break acceptance attribution", w)
					}
				}
			}
			if !found {
				t.Fatal("processing witness lost")
			}
		})
	}
}
