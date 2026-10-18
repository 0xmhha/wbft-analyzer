package messages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft/codec"
)

func selectedFrameFixture(t *testing.T) (Prepared, []Record, []byte) {
	t.Helper()
	payload := vote(t, codec.CodePrepare)
	first, second := frame(9007199254740993, payload), frame(9007199254740994, payload)
	first["dir"], second["dir"] = "in", "in"
	in := writeFrames(t, []map[string]any{first, second}, payload)
	summary, err := Fingerprint(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	p := Prepared{Input: in, Summary: summary}
	rows := []Record{}
	_, err = Read(t.Context(), p, "7", genesis, func(r Record) error { rows = append(rows, r); return nil })
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	return p, rows, payload
}

func TestSelectedFramesKeepIndependentBytesAndPrivateEncoding(t *testing.T) {
	p, rows, payload := selectedFrameFixture(t)
	rows[0], rows[1] = rows[1], rows[0]
	got, err := SelectedFramePayloads(t.Context(), p, rows, "7", genesis)
	if err != nil || len(got) != 2 || got[0].Code != 0x13 || got[1].Code != 0x13 || !bytes.Equal(got[0].Payload, payload) || !bytes.Equal(got[1].Payload, payload) {
		t.Fatal(got, err)
	}
	encoded, err := json.Marshal(got)
	if err != nil || string(encoded) != "[{},{}]" {
		t.Fatal("execution payload became persisted metadata", string(encoded), err)
	}
	got[0].Payload[0] ^= 0xff
	if !bytes.Equal(got[1].Payload, payload) {
		t.Fatal("different frame positions alias mutable payload bytes")
	}
}

func TestSelectedFramesFollowRequestedOrderAcrossDifferentMessages(t *testing.T) {
	prepare, commit := vote(t, codec.CodePrepare), vote(t, codec.CodeCommit)
	first, second := frame(9007199254740993, prepare), frame(9007199254740994, commit)
	first["dir"], second["dir"], second["code"] = "in", "in", "0x14"
	in := writeFrames(t, []map[string]any{first, second}, prepare)
	sum := sha256.Sum256(commit)
	hash := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Join(in.Path, "payloads", hash[:2]), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.Path, "payloads", hash[:2], hash), commit, 0600); err != nil {
		t.Fatal(err)
	}
	summary, err := Fingerprint(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	p := Prepared{Input: in, Summary: summary}
	rows := []Record{}
	_, err = Read(t.Context(), p, "7", genesis, func(r Record) error { rows = append(rows, r); return nil })
	if err != nil || len(rows) != 2 || rows[1].Seq != "9007199254740994" {
		t.Fatal(rows, err)
	}
	got, err := SelectedFramePayloads(t.Context(), p, []Record{rows[1], rows[0]}, "7", genesis)
	if err != nil || len(got) != 2 || got[0].Code != 0x14 || got[1].Code != 0x13 || !bytes.Equal(got[0].Payload, commit) || !bytes.Equal(got[1].Payload, prepare) {
		t.Fatal("selection was reordered or rebound", got, err)
	}
}

func TestSelectedFramesRefuseChangedPhysicalBytes(t *testing.T) {
	p, rows, _ := selectedFrameFixture(t)
	hash := rows[0].PayloadSHA256
	if err := os.WriteFile(filepath.Join(p.Input.Path, "payloads", hash[:2], hash), []byte("changed synthetic input"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := SelectedFramePayloads(t.Context(), p, rows, "7", genesis); err == nil || got != nil {
		t.Fatal("changed source exposed execution bytes", got, err)
	}
}

func TestSelectedFramesRefuseWholeSelectionOnForeignOrChangedRow(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Prepared, []Record) []Record
	}{
		{"duplicate coordinate", func(_ *Prepared, r []Record) []Record { return []Record{r[0], r[0]} }},
		{"foreign peer", func(_ *Prepared, r []Record) []Record { r[1].Peer = self; return r }},
		{"foreign run", func(_ *Prepared, r []Record) []Record { r[1].Run = "other-run"; return r }},
		{"changed view", func(_ *Prepared, r []Record) []Record { r[1].Height = "1"; return r }},
		{"outgoing frame", func(_ *Prepared, r []Record) []Record { r[1].Dir = "out"; return r }},
		{"missing coordinate", func(_ *Prepared, r []Record) []Record { r[1].Ordinal = 99; return r }},
		{"changed fingerprint", func(p *Prepared, r []Record) []Record { p.Summary.SHA256 = "changed"; return r }},
		{"journal instead of frames", func(p *Prepared, r []Record) []Record { p.Input.Kind = "journal"; return r }},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, rows, _ := selectedFrameFixture(t)
			rows = test.change(&p, rows)
			got, err := SelectedFramePayloads(t.Context(), p, rows, "7", genesis)
			if err == nil || got != nil {
				t.Fatal("partial or foreign selection exposed bytes", got, err)
			}
		})
	}
}

func TestSelectedFramesEnforceAggregateByteBoundAndCancellation(t *testing.T) {
	p, rows, payload := selectedFrameFixture(t)
	if got, err := selectedFramePayloads(t.Context(), p, rows, "7", genesis, 2*len(payload)); err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
	if got, err := selectedFramePayloads(t.Context(), p, rows, "7", genesis, 2*len(payload)-1); err == nil || got != nil {
		t.Fatal("aggregate byte limit allowed partial output", got, err)
	}
	if got, err := SelectedFramePayloads(t.Context(), p, make([]Record, MaxSelectedFrames+1), "7", genesis); err == nil || got != nil {
		t.Fatal("record bound bypassed", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := SelectedFramePayloads(ctx, p, rows, "7", genesis); err != context.Canceled || got != nil {
		t.Fatal(got, err)
	}
}
