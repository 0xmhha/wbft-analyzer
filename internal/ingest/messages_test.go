package ingest

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

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
