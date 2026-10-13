package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/inputs"
	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func ownedDataset(t *testing.T, s *Store, name, root string) (Dataset, inputs.Namespace, messages.ArchivedFile) {
	t.Helper()
	ctx := context.Background()
	d, release, e := s.BeginMessages(ctx, NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("a", 64)}, name, json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	data := []byte("hand-authored synthetic journal bytes")
	dir := t.TempDir()
	filename := "00000000000000000000.wal"
	if e = os.WriteFile(filepath.Join(dir, filename), data, 0600); e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(data)
	sha := hex.EncodeToString(h[:])
	sum := messages.Summary{ID: "journal", Kind: "journal", Node: "node", SHA256: sha, Files: []messages.File{{Name: filename, SHA256: sha, Bytes: int64(len(data))}}}
	if e = s.PutMessageInput(ctx, d.ID, sum); e != nil {
		t.Fatal(e)
	}
	n, e := s.ClaimInputStorage(ctx, d.ID, root)
	if e != nil {
		t.Fatal(e)
	}
	f, e := messages.Archive(ctx, n.Directory(), []messages.Prepared{{Input: messages.Input{ID: "journal", Path: dir}, Summary: sum}})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.PutInputFiles(ctx, d.ID, "journal", f["journal"]); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishRange(ctx, d.ID, 0, ""); e != nil {
		t.Fatal(e)
	}
	return d, n, f["journal"][0]
}
func TestDatasetDeletionOwnsIdenticalObjectsAndFencesActiveReaders(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	a, na, fa := ownedDataset(t, s, "first", root)
	b, nb, fb := ownedDataset(t, s, "second", root)
	if fa.SHA256 != fb.SHA256 || fa.Path == fb.Path {
		t.Fatal("objects shared across dataset namespaces", fa, fb)
	}
	lease, e := s.DatasetReadLease(ctx, a.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DeleteDataset(ctx, a.NetworkID, a.ID, a.Name); !errors.Is(e, ErrDatasetBusy) {
		t.Fatal(e)
	}
	lease()
	if _, e = s.DeleteDataset(ctx, a.NetworkID, a.ID, "wrong"); !errors.Is(e, ErrDatasetConfirm) {
		t.Fatal(e)
	}
	job, e := s.EnqueueReexec(ctx, ReexecJob{Dataset: a.ID, Input: "journal", Source: "source", SourceSHA: strings.Repeat("b", 64), From: "1", To: "1", Mode: "closed"})
	if e != nil {
		t.Fatal(e)
	}
	run, e := s.BeginReexec(ctx, a.ID, "journal", "1", "1", fa.Path, reexec.Result{Status: "running", ChainSHA: fa.SHA256})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.PutReexecStep(ctx, run, reexec.Step{Ordinal: 1, Height: "1", Class: "match"}); e != nil {
		t.Fatal(e)
	}

	if _, e = s.pool.Exec(ctx, `INSERT INTO heights(network_id,index_,hash,fact) VALUES($1,1,$2,'{}')`, a.NetworkID, "0x"+strings.Repeat("c", 64)); e != nil {
		t.Fatal(e)
	}
	got, e := s.DeleteDataset(ctx, a.NetworkID, a.ID, a.Name)
	if e != nil || got.Status != "deleted" || got.Files != 1 {
		t.Fatal(got, e)
	}
	if _, e = os.Stat(fa.Path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("owned object remains", e)
	}
	if _, e = os.Stat(fb.Path); e != nil {
		t.Fatal("other dataset bytes deleted", e)
	}
	if e = na.Verify(); e != nil {
		t.Fatal(e)
	}
	if e = nb.Verify(); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReexecJob(ctx, a.ID, job.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	if _, e = s.DatasetReadLease(ctx, a.ID); !errors.Is(e, ErrDatasetDeleting) {
		t.Fatal(e)
	}
	again, e := s.DeleteDataset(ctx, a.NetworkID, a.ID, a.Name)
	if e != nil || again.Status != "deleted" || again.Files != got.Files {
		t.Fatal(again, e)
	}

	var canonical int
	if e = s.pool.QueryRow(ctx, `SELECT count(*) FROM heights WHERE network_id=$1`, a.NetworkID).Scan(&canonical); e != nil || canonical != 1 {
		t.Fatal("shared canonical facts deleted", canonical, e)
	}
	ds, e := s.Datasets(ctx, b.NetworkID)
	if e != nil || len(ds) != 1 || ds[0].ID != b.ID {
		t.Fatal(ds, e)
	}
}
func TestDatasetDeletionRefusesUnmanagedInputsThenAdoptsVerifiedCopy(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	d, n, f := ownedDataset(t, s, "legacy", t.TempDir())
	// Simulate an older shared CAS reference without moving or removing bytes.
	if _, e := s.pool.Exec(ctx, `DELETE FROM dataset_storage WHERE dataset_id=$1`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DeleteDataset(ctx, d.NetworkID, d.ID, d.Name); !errors.Is(e, ErrUnmanagedInputs) {
		t.Fatal(e)
	}
	if e := s.AdoptDatasetInputs(ctx, d.NetworkID, d.ID, filepath.Join(t.TempDir(), "adopt")); e != nil {
		t.Fatal(e)
	}
	refs, e := s.InputFiles(ctx, d.ID, "journal")
	if e != nil || len(refs) != 1 || refs[0].Path == f.Path {
		t.Fatal(refs, e)
	}
	if _, e = s.DeleteDataset(ctx, d.NetworkID, d.ID, d.Name); e != nil {
		t.Fatal(e)
	}
	if b, e := os.ReadFile(f.Path); e != nil || string(b) != "hand-authored synthetic journal bytes" {
		t.Fatal("legacy shared bytes changed", b, e)
	}
	if e = n.Verify(); e != nil {
		t.Fatal(e)
	}
}
func TestDatasetDeletionResumesCommittedIntentAndPreservesFollowDependency(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	d, n, f := ownedDataset(t, s, "interrupted", t.TempDir())
	owner, e := s.StorageOwner(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `INSERT INTO dataset_deletions(dataset_id,network_id,name,status,root,token,owner,files,bytes) VALUES($1,$2,$3,'deleting',$4,$5,$6,1,$7)`, d.ID, d.NetworkID, d.Name, n.Root, n.Token, owner, f.Bytes); e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `UPDATE datasets SET status='deleting' WHERE id=$1`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.EnqueueReexec(ctx, ReexecJob{Dataset: d.ID, Input: "journal", SourceSHA: strings.Repeat("b", 64), From: "1", To: "1", Mode: "closed"}); !errors.Is(e, ErrDatasetDeleting) {
		t.Fatal(e)
	}
	if _, _, e = s.BeginMessages(ctx, NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("a", 64)}, d.Name, json.RawMessage(`{}`)); !errors.Is(e, ErrDatasetDeleting) {
		t.Fatal(e)
	}
	// Simulate a process stopping after object removal but before row cleanup.
	if e = os.Remove(f.Path); e != nil {
		t.Fatal(e)
	}
	got, e := s.DeleteDataset(ctx, d.NetworkID, d.ID, d.Name)
	if e != nil || got.Status != "deleted" {
		t.Fatal(got, e)
	}
}

func TestRestoredNamespaceRequiresAdoptionAndPreservesOriginal(t *testing.T) {
	original, _ := testStore(t)
	clone, _ := testStore(t)
	ctx := context.Background()
	for _, s := range []*Store{original, clone} {
		if _, e := s.Migrate(ctx); e != nil {
			t.Fatal(e)
		}
	}
	d, n, f := ownedDataset(t, original, "source-dataset", t.TempDir())
	c, release, e := clone.BeginMessages(ctx, NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("a", 64)}, "restored-dataset", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	in, e := original.MessageInputs(ctx, d.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = clone.PutMessageInput(ctx, c.ID, in[0].Summary); e != nil {
		t.Fatal(e)
	}
	if e = clone.PutInputFiles(ctx, c.ID, "journal", []messages.ArchivedFile{f}); e != nil {
		t.Fatal(e)
	}
	if _, e = clone.pool.Exec(ctx, `INSERT INTO dataset_storage(dataset_id,root,token,owner) VALUES($1,$2,$3,$4)`, c.ID, n.Root, n.Token, n.Owner); e != nil {
		t.Fatal(e)
	}
	info, e := clone.DatasetInputStorage(ctx, c.NetworkID, c.ID)
	if e != nil || info.State != "foreign" {
		t.Fatal(info, e)
	}
	if _, e = clone.DeleteDataset(ctx, c.NetworkID, c.ID, c.Name); !errors.Is(e, inputs.ErrOwnership) {
		t.Fatal("restored namespace deleted source bytes", e)
	}
	if e = clone.AdoptDatasetInputs(ctx, c.NetworkID, c.ID, n.Root); e != nil {
		t.Fatal(e)
	}
	refs, e := clone.InputFiles(ctx, c.ID, "journal")
	if e != nil || refs[0].Path == f.Path {
		t.Fatal(refs, e)
	}
	if _, e = clone.DeleteDataset(ctx, c.NetworkID, c.ID, c.Name); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(f.Path); e != nil {
		t.Fatal("original database input removed", e)
	}
	info, e = original.DatasetInputStorage(ctx, d.NetworkID, d.ID)
	if e != nil || info.State != "owned" || info.Files != 1 {
		t.Fatal(info, e)
	}
}

func TestDatasetDeletionRefusesFollowReferencesAndRunningJobs(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	d, _, f := ownedDataset(t, s, "referenced", t.TempDir())
	follow, release, e := s.BeginFollow(ctx, NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("a", 64)}, "follow", json.RawMessage(`{}`), 1, "parent")
	if e != nil {
		t.Fatal(e)
	}
	release()
	if _, e = s.pool.Exec(ctx, `INSERT INTO follow_batches(dataset_id,from_index,to_index,headers_dataset,observations_dataset) VALUES($1,1,1,$2,$2)`, follow.ID, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DeleteDataset(ctx, d.NetworkID, d.ID, d.Name); !errors.Is(e, ErrDatasetReferenced) {
		t.Fatal(e)
	}
	if _, e = os.Stat(f.Path); e != nil {
		t.Fatal(e)
	}
	if _, e = s.pool.Exec(ctx, `DELETE FROM follow_batches WHERE dataset_id=$1`, follow.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.EnqueueReexec(ctx, ReexecJob{Dataset: d.ID, Input: "journal", SourceSHA: strings.Repeat("b", 64), From: "1", To: "1", Mode: "closed"}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ClaimReexecJob(ctx, "worker"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DeleteDataset(ctx, d.NetworkID, d.ID, d.Name); !errors.Is(e, ErrDatasetBusy) {
		t.Fatal(e)
	}
	if _, e = os.Stat(f.Path); e != nil {
		t.Fatal(e)
	}
}
