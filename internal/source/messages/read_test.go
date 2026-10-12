package messages

import (
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

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

const self = "0x0000000000000000000000000000000000000001"
const genesis = "0x0000000000000000000000000000000000000000000000000000000000000000"

func vote(t *testing.T, code codec.Code) []byte {
	t.Helper()
	h, _ := new(big.Int).SetString("18446744073709551617", 10)
	r, _ := new(big.Int).SetString("340282366920938463463374607431768211456", 10)
	round, e := types.RoundFromBig(r)
	if e != nil {
		t.Fatal(e)
	}
	m := &codec.Message{Code: code, View: types.View{Sequence: types.MustHeightFromBig(h), Round: round}, Digest: types.Hash{1}}
	// Deterministic, public test-only scalar, never an operational key.
	key := make([]byte, 32)
	key[31] = 1
	k, e := ecdsa.PrivateKeyFromBytes(key)
	if e != nil {
		t.Fatal(e)
	}
	b, e := codec.SigningPayload(m, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	m.Signature, e = ecdsa.SignData(b, k)
	if e != nil {
		t.Fatal(e)
	}
	b, e = codec.EncodeMessage(m)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func syntheticJournal(t *testing.T) Input {
	t.Helper()
	dir := t.TempDir()
	a := types.Address{}
	a[19] = 1
	peer := types.Address{}
	peer[19] = 2
	w, e := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Self: a, Run: "synthetic", ChainID: big.NewInt(7), Core: journal.CoreOptions{ChainConfig: []byte("NEVER_STORED"), Improvements: 1}})
	if e != nil {
		t.Fatal(e)
	}
	w.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peer, Event: "attached", Remote: "NEVER_STORED"}})
	for i, c := range []codec.Code{codec.CodePrepare, codec.CodeCommit, codec.CodeRoundChange} {
		if i == 2 {
			w.Put(journal.Record{Body: &journal.PeerRec{PeerIdx: 1, Addr: peer, Event: "closed"}})
		}
		b := vote(t, c)
		w.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.In, PeerIdx: 1, Code: uint64(c), Payload: b, DedupKey: codec.DedupKey(b), Mono: time.Duration(3 - i), WallNs: 1577836800000000000 + int64(i), Offer: "queued", Engine: "running"}})
	}
	w.Put(journal.Record{Body: &journal.OutcomeRec{Code: 0x13, Outcome: event.Accept, Reason: "NEVER_STORED", Step: 5, Row: -1}})
	w.Put(journal.Record{Body: &journal.StepRec{Input: []byte("NEVER_STORED"), Env: [][]byte{[]byte("NEVER_STORED")}, Step: 5, HeadNumber: types.HeightFromUint64(8)}})
	w.Put(journal.Record{Body: &journal.GapRec{Dropped: 2, FirstMono: 1, LastMono: 2}})
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return Input{ID: "journal-1", Kind: "journal", Node: self, Path: dir}
}
func TestJournalMetadataIdentityAndTail(t *testing.T) {
	in := syntheticJournal(t)
	sum, e := Fingerprint(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	p := Prepared{in, sum}
	xs := []Record{}
	s, e := Read(context.Background(), p, "7", genesis, func(r Record) error { xs = append(xs, r); return nil })
	if e != nil || s.Frames != 3 || s.Decoded != 3 || s.GapRecords != 1 || s.ClockRegressions < 2 {
		t.Fatal(s, e)
	}
	raw, _ := json.Marshal(xs)
	if strings.Contains(string(raw), "NEVER_STORED") {
		t.Fatal("private bytes stored")
	}
	phases := map[string]bool{}
	for _, r := range xs {
		if r.Type == "frame" {
			phases[r.Phase] = true
			if r.Height != "18446744073709551617" || r.Round != "340282366920938463463374607431768211456" || r.Signature != "recovered" || r.Signer == "" || r.Offset == nil || r.Peer == "" {
				t.Fatal(r)
			}
		}
	}
	if len(phases) != 3 {
		t.Fatal(phases)
	}
	if _, e = Read(context.Background(), p, "8", genesis, func(Record) error { return nil }); e == nil {
		t.Fatal("network mismatch accepted")
	}
	// A torn final frame is EOF to the WBFT reader; this importer must expose it.
	path := filepath.Join(in.Path, "00000000000000000000.wal")
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.Write([]byte{1, 2, 3})
	f.Close()
	sum, e = Fingerprint(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	s, e = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(Record) error { return nil })
	if e == nil || s.Frames != 3 || !strings.Contains(e.Error(), "incomplete tail") {
		t.Fatal(s, e)
	}
	// Damage a checksum, which is distinct from an incomplete final frame.
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	b[4] ^= 1
	_ = os.WriteFile(path, b, 0600)
	sum, e = Fingerprint(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(Record) error { return nil }); e == nil {
		t.Fatal("CRC corruption accepted")
	}
}
func writeFrames(t *testing.T, records []map[string]any, payload []byte) Input {
	t.Helper()
	dir := t.TempDir()
	var rows strings.Builder
	for _, r := range records {
		b, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		rows.Write(b)
		rows.WriteByte('\n')
	}
	if e := os.WriteFile(filepath.Join(dir, "frames-synthetic.jsonl"), []byte(rows.String()), 0600); e != nil {
		t.Fatal(e)
	}
	if payload != nil {
		sum := sha256.Sum256(payload)
		h := hex.EncodeToString(sum[:])
		d := filepath.Join(dir, "payloads", h[:2])
		_ = os.MkdirAll(d, 0700)
		_ = os.WriteFile(filepath.Join(d, h), payload, 0600)
	}
	return Input{ID: "frames-1", Kind: "frames", Node: self, Path: dir}
}
func frame(seq uint64, payload []byte) map[string]any {
	sum := sha256.Sum256(payload)
	return map[string]any{"v": 1, "type": "frame", "node": self, "run": "synthetic", "seq": seq, "t_wall": "2020-01-01T00:00:00.000000001Z", "t_mono_ns": 10, "dir": "out", "peer": "0x0000000000000000000000000000000000000002", "code": "0x13", "size": len(payload), "payload_sha256": hex.EncodeToString(sum[:]), "dedup_key": codec.DedupKey(payload).Hex(), "reason": "NEVER_STORED", "payload": "NEVER_STORED"}
}
func TestFramesPayloadValidationAndUnorderedSequence(t *testing.T) {
	payload := vote(t, codec.CodePrepare)
	a, b := frame(3, payload), frame(2, payload)
	in := writeFrames(t, []map[string]any{a, b}, payload)
	sum, e := Fingerprint(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	xs := []Record{}
	s, e := Read(context.Background(), Prepared{in, sum}, "7", genesis, func(r Record) error { xs = append(xs, r); return nil })
	if e != nil || s.Decoded != 2 || xs[0].Seq != "3" || xs[1].Seq != "2" || xs[0].Write != "no_error_recorded" || xs[0].ClockSource != "recorded" {
		t.Fatal(s, xs, e)
	}
	raw, _ := json.Marshal(xs)
	if strings.Contains(string(raw), "NEVER_STORED") {
		t.Fatal("unsafe frame metadata")
	}
	a["dedup_key"] = genesis
	in = writeFrames(t, []map[string]any{a}, payload)
	sum, e = Fingerprint(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	// Zero key is missing metadata and is reconstructed from payload, not a mismatch.
	if _, e = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(r Record) error {
		if r.Key == "" {
			t.Fatal(r)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	a["dedup_key"] = "0x" + strings.Repeat("a", 64)
	in = writeFrames(t, []map[string]any{a}, payload)
	sum, _ = Fingerprint(context.Background(), in)
	if _, e = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(r Record) error {
		if r.Decode != "key_mismatch" || r.Height != "" {
			t.Fatal(r)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	in = writeFrames(t, []map[string]any{b, b}, payload)
	sum, _ = Fingerprint(context.Background(), in)
	if _, e = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(Record) error { return nil }); e == nil {
		t.Fatal("duplicate seq accepted")
	}
	in = writeFrames(t, []map[string]any{b}, []byte("WRONG_BYTES"))
	sum, _ = Fingerprint(context.Background(), in)
	// Referenced payload is absent: retain the frame as explicitly undecoded.
	if _, e = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(r Record) error {
		if r.Decode != "missing_payload" {
			t.Fatal(r)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	h := b["payload_sha256"].(string)
	_ = os.MkdirAll(filepath.Join(in.Path, "payloads", h[:2]), 0700)
	_ = os.WriteFile(filepath.Join(in.Path, "payloads", h[:2], h), []byte("WRONG_BYTES"), 0600)
	sum, _ = Fingerprint(context.Background(), in)
	if _, e = Read(context.Background(), Prepared{in, sum}, "7", genesis, func(Record) error { return nil }); e == nil {
		t.Fatal("payload SHA mismatch accepted")
	}
}
func TestArtifactBoundsAndCancellation(t *testing.T) {
	in := syntheticJournal(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Fingerprint(ctx, in); e == nil {
		t.Fatal("cancellation ignored")
	}
	_ = os.Symlink(filepath.Join(in.Path, "00000000000000000000.wal"), filepath.Join(in.Path, "00000000000000000001.wal"))
	if _, e := Fingerprint(context.Background(), in); e == nil {
		t.Fatal("symlink accepted")
	}
	if uniqueObject([]byte(`{"seq":1,"seq":2}`)) {
		t.Fatal("duplicate JSON accepted")
	}
	if uniqueObject([]byte(`{"seq":1} {}`)) {
		t.Fatal("trailing JSON accepted")
	}
}
