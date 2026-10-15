package messages

import (
	"bytes"
	"context"
	"testing"

	"github.com/0xmhha/wbft/codec"
)

func TestSelectedPayloadRequiresExactImmutableIncomingRow(t *testing.T) {
	in := syntheticJournal(t)
	summary, err := Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	prepared := Prepared{Input: in, Summary: summary}
	var selected Record
	_, err = Read(context.Background(), prepared, "7", genesis, func(r Record) error {
		if r.Type == "frame" && r.Phase == "PREPARE" {
			selected = r
		}
		return nil
	})
	if err != nil || selected.Input == "" {
		t.Fatal(selected, err)
	}
	payload, code, err := SelectedPayload(context.Background(), prepared, selected, "7", genesis)
	if err != nil || code != uint64(codec.CodePrepare) || !bytes.Equal(payload, vote(t, codec.CodePrepare)) {
		t.Fatal(code, err)
	}
	for _, alter := range []func(*Record){func(r *Record) { r.Ordinal++ }, func(r *Record) { r.Peer = self }, func(r *Record) { r.Dir = "out" }, func(r *Record) { r.Capture = "999" }, func(r *Record) { r.File = "../other" }, func(r *Record) { r.PayloadSHA256 = "" }} {
		bad := selected
		alter(&bad)
		if _, _, err := SelectedPayload(context.Background(), prepared, bad, "7", genesis); err == nil {
			t.Fatal("foreign or changed source accepted", bad)
		}
	}
	prepared.Summary.SHA256 = "changed"
	if _, _, err := SelectedPayload(context.Background(), prepared, selected, "7", genesis); err == nil {
		t.Fatal("changed snapshot accepted")
	}
}

func TestSelectedPayloadReadsAnExactFrameCopy(t *testing.T) {
	payload := vote(t, codec.CodePrepare)
	row := frame(9007199254740993, payload)
	row["dir"] = "in"
	in := writeFrames(t, []map[string]any{row}, payload)
	summary, err := Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	prepared := Prepared{Input: in, Summary: summary}
	var selected Record
	_, err = Read(context.Background(), prepared, "7", genesis, func(r Record) error { selected = r; return nil })
	if err != nil || selected.Seq != "9007199254740993" {
		t.Fatal(selected, err)
	}
	got, code, err := SelectedPayload(context.Background(), prepared, selected, "7", genesis)
	if err != nil || code != 0x13 || !bytes.Equal(got, payload) {
		t.Fatal(code, err)
	}
}
