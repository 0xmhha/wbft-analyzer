package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func exportReady(t *testing.T, s *Store, name string) (Dataset, func()) {
	t.Helper()
	d, release, err := s.BeginMessages(context.Background(), NetworkKey{ChainID: "7", GenesisHash: "genesis", Name: "export"}, name, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(context.Background(), `UPDATE datasets SET status='complete' WHERE id=$1`, d.ID); err != nil {
		t.Fatal(err)
	}
	return d, release
}
func exportRows(t *testing.T, out, table string) []map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(out, table+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	result := []map[string]json.RawMessage{}
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r map[string]json.RawMessage
		if err = json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		result = append(result, r)
	}
	return result
}
func assertBundleDigests(t *testing.T, out string, m ExportManifest) {
	t.Helper()
	for _, f := range append(m.Tables, m.Objects...) {
		b, err := os.ReadFile(filepath.Join(out, f.Path))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if int64(len(b)) != f.Bytes || hex.EncodeToString(sum[:]) != f.SHA256 {
			t.Fatalf("bundle digest mismatch: %s", f.Path)
		}
	}
	var saved ExportManifest
	b, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &saved); err != nil || saved.Schema != "wbft-analyzer-dataset/1" {
		t.Fatal("missing committed manifest")
	}
}

func TestExportOwnershipAndBoundaries(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, release := exportReady(t, s, "chosen")
	defer release()
	parent := t.TempDir()
	out := filepath.Join(parent, "busy")
	if _, err := s.ExportDataset(ctx, d.Name, out, "public"); !errors.Is(err, ErrDatasetBusy) {
		t.Fatalf("export during import: %v", err)
	}
	release()
	other, r := exportReady(t, s, "unrelated")
	r()
	if _, err := s.pool.Exec(ctx, `INSERT INTO header_copies(dataset_id,node,index_,hash,copy) VALUES($1,'one',1,'one','{}'),($2,'other',2,'two','{}');`, d.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO heights(network_id,index_,hash,fact) VALUES($1,1,'one','{}'),($1,2,'two','{}')`, d.NetworkID); err != nil {
		t.Fatal(err)
	}
	m, err := s.ExportDataset(ctx, d.Name, out, "public")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Datasets) != 1 || m.Datasets[0] != d.ID || m.Visibility != "public" || m.Target != "public" {
		t.Fatalf("scope: %+v", m)
	}
	if rows := exportRows(t, out, "datasets"); len(rows) != 1 || string(rows[0]["name"]) != `"chosen"` {
		t.Fatal("unrelated dataset leaked")
	}
	if rows := exportRows(t, out, "heights"); len(rows) != 1 || string(rows[0]["index_"]) != "1" {
		t.Fatal("unrelated canonical height leaked")
	}
	assertBundleDigests(t, out, m)
	before, _ := os.ReadFile(filepath.Join(out, "manifest.json"))
	if _, err = s.ExportDataset(ctx, d.Name, out, "public"); err == nil {
		t.Fatal("existing output replaced")
	}
	after, _ := os.ReadFile(filepath.Join(out, "manifest.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("existing output changed")
	}
	if _, err = s.pool.Exec(ctx, `UPDATE datasets SET visibility='private' WHERE id=$1`, d.ID); err != nil {
		t.Fatal(err)
	}
	refusal := filepath.Join(parent, "refused")
	if _, err = s.ExportDataset(ctx, d.Name, refusal, "public"); !errors.Is(err, ErrExportPrivate) {
		t.Fatalf("private export accepted: %v", err)
	}
	if _, err = os.Stat(refusal); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refusal created output")
	}
	if _, err = s.ExportDataset(ctx, d.Name, refusal, "private"); !errors.Is(err, ErrBuildScope) {
		t.Fatalf("stock build accessed private dataset: %v", err)
	}
}

func TestExportObjectsSourcesAndFailureCleanup(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, release := exportReady(t, s, "objects")
	defer release()
	inputRoot := t.TempDir()
	if err := os.Chmod(inputRoot, 0700); err != nil {
		t.Fatal(err)
	}
	n, err := s.ClaimInputStorage(ctx, d.ID, inputRoot)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("{\"retained\":true}\n")
	sum := sha256.Sum256(raw)
	sha := hex.EncodeToString(sum[:])
	path := filepath.Join(n.Directory(), sha)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	file := messages.ArchivedFile{Name: "journal", Path: path, SHA256: sha, Bytes: int64(len(raw))}
	if _, err = s.pool.Exec(ctx, `INSERT INTO message_inputs(dataset_id,input_id,node,summary,stats) VALUES($1,'journal','node','{}','{}')`, d.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.PutInputFiles(ctx, d.ID, "journal", []messages.ArchivedFile{file}); err != nil {
		t.Fatal(err)
	}
	snap, _ := json.Marshal(scenario.SourceSnapshot{Chain: file})
	if _, err = s.pool.Exec(ctx, `INSERT INTO scenario_sources(dataset_id,source_id,declaration_sha256,source_sha256,execution_sha256,snapshot) VALUES($1,'source',$2,$2,'',$3)`, d.ID, sha, snap); err != nil {
		t.Fatal(err)
	}
	release()
	parent := t.TempDir()
	out := filepath.Join(parent, "bundle")
	m, err := s.ExportDataset(ctx, d.Name, out, "private")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Objects) != 1 {
		t.Fatal("objects were omitted or duplicated")
	}
	assertBundleDigests(t, out, m)
	if rows := exportRows(t, out, "input_files"); len(rows) != 1 || string(rows[0]["path"]) != `"object-`+sha+`"` {
		t.Fatal("input reference not portable")
	}
	sourceRows := exportRows(t, out, "scenario_sources")
	if len(sourceRows) != 1 || bytes.Contains(sourceRows[0]["snapshot"], []byte(n.Root)) || !bytes.Contains(sourceRows[0]["snapshot"], []byte("object-"+sha)) {
		t.Fatal("scenario reference not portable")
	}
	if err = os.WriteFile(path, bytes.Repeat([]byte("x"), len(raw)), 0600); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(parent, "broken")
	if _, err = s.ExportDataset(ctx, d.Name, broken, "private"); err == nil {
		t.Fatal("corrupt object accepted")
	}
	if _, err = os.Stat(broken); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed export left output")
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.ExportDataset(cancelCtx, d.Name, filepath.Join(parent, "cancelled"), "private"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestExportDependencyPrivacyAndSchemaCoverage(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, ra := exportReady(t, s, "root")
	ra()
	b, rb := exportReady(t, s, "dependency")
	rb()
	if _, err := s.pool.Exec(ctx, `INSERT INTO message_pair_dependencies(dataset_id,source_id,progress,status,metadata) VALUES($1,$2,0,'complete','{}')`, a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "closure")
	m, err := s.ExportDataset(ctx, a.Name, out, "public")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Datasets) != 2 || len(exportRows(t, out, "datasets")) != 2 {
		t.Fatal("dependency was not bundled")
	}
	if _, err = s.pool.Exec(ctx, `UPDATE datasets SET visibility='private' WHERE id=$1`, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ExportDataset(ctx, a.Name, filepath.Join(t.TempDir(), "refuse"), "public"); !errors.Is(err, ErrExportPrivate) {
		t.Fatalf("private dependency leaked: %v", err)
	}
	if _, err = s.pool.Exec(ctx, `UPDATE datasets SET visibility='public'; CREATE TABLE future_data(id bigint)`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ExportDataset(ctx, a.Name, filepath.Join(t.TempDir(), "future"), "public"); err == nil || !strings.Contains(err.Error(), "ownership rule") {
		t.Fatalf("unknown table silently omitted: %v", err)
	}
}
