package ingest

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func TestMessageIORetainedInputAndExactStoredSelector(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	a := types.Address{19: 1}
	w, e := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Self: a, Run: "synthetic-io", ChainID: big.NewInt(7)})
	if e != nil {
		t.Fatal(e)
	}
	w.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, Mono: 9007199254740994, WallNs: 1577836800000000200, Code: 0x13, Payload: []byte{0xc0}, Write: "ok", IO: &journal.IOInterval{StartMono: 0, EndMono: 9007199254740993, StartWallNs: 1577836800000000100, EndWallNs: 1577836800000000090}}})
	w.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, Code: 0x13, Payload: []byte{0xc0}, Write: "not_attached"}})
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	m := messages.Manifest{Format: messages.Format, Name: "io-retention", Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Clock: messages.Clock{Model: "unknown"}, Inputs: []messages.Input{{ID: "journal", Kind: "journal", Node: strings.ToLower(a.Hex()), Path: dir}}}
	archive := filepath.Join(t.TempDir(), "retained")
	one, e := MessagesWithInputs(ctx, s, m, archive)
	if e != nil {
		t.Fatal(e)
	}
	two, e := MessagesWithInputs(ctx, s, m, archive)
	if e != nil || !two.Skipped || one.DatasetID != two.DatasetID {
		t.Fatal(two, e)
	}
	rs, e := s.MessageRecords(ctx, one.DatasetID, store.MessageFilter{Type: "frame", Limit: 10})
	if e != nil || len(rs) != 2 {
		t.Fatal(rs, e)
	}
	if rs[0].IO == nil || rs[0].IO.StartMono != "0" || rs[0].IO.EndMono != "9007199254740993" || rs[1].IO != nil {
		t.Fatal("stored interval changed or invented", rs)
	}
	selected, e := s.MessageRecordAt(ctx, one.DatasetID, rs[0].Input, rs[0].File, rs[0].Ordinal)
	if e != nil || !reflect.DeepEqual(selected, rs[0]) {
		t.Fatal("source selector changed I/O evidence", selected, e)
	}
	files, e := s.InputFiles(ctx, one.DatasetID, "journal")
	if e != nil || len(files) == 0 {
		t.Fatal(files, e)
	}
	for _, f := range files {
		if _, e = os.Stat(f.Path); e != nil {
			t.Fatal("retained original missing", e)
		}
	}
	raw, e := json.Marshal(selected)
	if e != nil || strings.Contains(string(raw), `"payload":`) || strings.Contains(string(raw), `"reason":`) {
		t.Fatal("raw fields escaped metadata", e)
	}
}

func TestMessageDatasetRetryIdentityAndPrefix(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	a := types.Address{}
	a[19] = 1
	w, e := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Self: a, Run: "synthetic", ChainID: big.NewInt(7)})
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 600; i++ {
		w.Put(journal.Record{Body: &journal.MsgRec{Dir: "in", Code: 0x13, Payload: []byte{0xc0}}})
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	m := messages.Manifest{Format: messages.Format, Name: "message-run", Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Clock: messages.Clock{Model: "unknown"}, Inputs: []messages.Input{{ID: "journal", Kind: "journal", Node: strings.ToLower(a.Hex()), Path: dir}}}
	one, e := Messages(ctx, s, m)
	if e != nil || one.Records != 601 || len(one.Inputs) != 1 || one.Inputs[0].Stats.Undecoded != 600 {
		t.Fatal(one, e)
	}
	two, e := Messages(ctx, s, m)
	if e != nil || !two.Skipped || one.DatasetID != two.DatasetID || one.Records != two.Records {
		t.Fatal(two, e)
	}
	rows, e := s.MessageRecords(ctx, one.DatasetID, store.MessageFilter{Type: "frame", Limit: 1000})
	if e != nil || len(rows) != 600 {
		t.Fatal(len(rows), e)
	}
	b, _ := json.Marshal(rows)
	if strings.Contains(string(b), `"payload":`) || strings.Contains(string(b), `"reason":`) {
		t.Fatal("payload persisted")
	}
	// Retention can be added to a completed metadata import without duplicating rows.
	archive := filepath.Join(t.TempDir(), "inputs")
	retained, e := MessagesWithInputs(ctx, s, m, archive)
	if e != nil || !retained.Skipped || retained.DatasetID != one.DatasetID {
		t.Fatal(retained, e)
	}
	files, e := s.InputFiles(ctx, one.DatasetID, "journal")
	if e != nil || len(files) == 0 {
		t.Fatal(files, e)
	}
	canonicalArchive, canonicalErr := filepath.EvalSymlinks(archive)
	if canonicalErr != nil {
		t.Fatal(canonicalErr)
	}
	for _, f := range files {
		if filepath.Dir(filepath.Dir(f.Path)) != filepath.Join(canonicalArchive, "datasets") || filepath.Base(f.Path) != f.SHA256 {
			t.Fatal(f)
		}
		if _, e = os.Stat(f.Path); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = MessagesWithInputs(ctx, s, m, filepath.Join(t.TempDir(), "inputs")); e == nil {
		t.Fatal("storage path conflict accepted")
	}
	// Storage refusal must not invalidate an already complete metadata dataset.
	dsBefore, e := s.Datasets(ctx, one.NetworkID)
	if e != nil || dsBefore[0].Status != "complete" {
		t.Fatal(dsBefore, e)
	}
	ds, e := s.Datasets(ctx, one.NetworkID)
	if e != nil || ds[0].Kind != "messages" || len(ds[0].Nodes) != 1 || ds[0].Status != "complete" {
		t.Fatal(ds, e)
	}
	// A new dataset preserves readable rows and fails, including on retry.
	path := filepath.Join(dir, "00000000000000000000.wal")
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.Write([]byte{1, 2, 3})
	f.Close()
	if _, e = Messages(ctx, s, m); e == nil {
		t.Fatal("changed input reused complete dataset")
	}
	m.Name = "damaged"
	one, e = Messages(ctx, s, m)
	if e == nil || one.Records != 601 {
		t.Fatal(one, e)
	}
	two, e = Messages(ctx, s, m)
	if e == nil || two.Records != 601 || two.Skipped || two.DatasetID != one.DatasetID {
		t.Fatal(two, e)
	}
	rows, e = s.MessageRecords(ctx, one.DatasetID, store.MessageFilter{Limit: 1000})
	if e != nil || len(rows) != 601 {
		t.Fatal("retry duplicated prefix", len(rows), e)
	}
	ds, e = s.Datasets(ctx, one.NetworkID)
	if e != nil || ds[1].Status != "failed" {
		t.Fatal(ds, e)
	}
	// Concurrent ownership is refused before writing.
	_, meta, e := messages.Prepare(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	_, release, e := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: m.Network.GenesisHash}, "damaged", meta)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if _, e = Messages(ctx, s, m); e == nil {
		t.Fatal("parallel importer accepted")
	}
}
