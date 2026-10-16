package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/inputs"
	"github.com/0xmhha/wbft-analyzer/internal/privacy"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/jackc/pgx/v5"
)

var ErrExportPrivate = errors.New("export: private data cannot be exported to a public target")

// ExportManifest describes a committed logical snapshot, not a publication or
// an automatic database restore. Table rows use the source schema's identities.
type ExportManifest struct {
	Schema        string       `json:"schema"`
	SchemaVersion int          `json:"schema_version"`
	Dataset       int64        `json:"dataset"`
	Datasets      []int64      `json:"datasets"`
	Visibility    string       `json:"visibility"`
	Target        string       `json:"target"`
	Tables        []ExportFile `json:"tables"`
	Objects       []ExportFile `json:"objects"`
	Excluded      []string     `json:"excluded"`
}
type ExportFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Rows   int64  `json:"rows,omitempty"`
}

type exportTable struct{ name, where string }

// Every data table has an explicit ownership rule. Operational configuration,
// deletion journals and physical storage ownership never travel with a dataset.
var exportTables = []exportTable{
	{"networks", `id IN (SELECT network_id FROM datasets WHERE id=ANY($1))`},
	{"datasets", `id=ANY($1)`},
	{"heights", `(network_id,index_) IN (SELECT d.network_id,h.index_ FROM header_copies h JOIN datasets d ON d.id=h.dataset_id WHERE d.id=ANY($1))`},
	{"seals", `(network_id,index_) IN (SELECT d.network_id,h.index_ FROM header_copies h JOIN datasets d ON d.id=h.dataset_id WHERE d.id=ANY($1))`},
	{"epochs", `(network_id,index_) IN (SELECT d.network_id,h.index_ FROM header_copies h JOIN datasets d ON d.id=h.dataset_id WHERE d.id=ANY($1))`},
	{"header_copies", `dataset_id=ANY($1)`},
	{"reports", `dataset_id=ANY($1)`},
	{"report_inputs", `report_id IN (SELECT id FROM reports WHERE dataset_id=ANY($1))`},
	{"results", `report_id IN (SELECT id FROM reports WHERE dataset_id=ANY($1))`},
	{"observations", `report_id IN (SELECT id FROM reports WHERE dataset_id=ANY($1))`},
	{"trend_points", `report_id IN (SELECT id FROM reports WHERE dataset_id=ANY($1))`},
	{"log_inputs", `dataset_id=ANY($1)`}, {"log_events", `dataset_id=ANY($1)`},
	{"replay_indexes", `dataset_id=ANY($1)`}, {"replay_keyframes", `dataset_id=ANY($1)`},
	{"message_inputs", `dataset_id=ANY($1)`}, {"message_records", `dataset_id=ANY($1)`},
	{"message_pair_indexes", `dataset_id=ANY($1)`}, {"message_pairs", `dataset_id=ANY($1)`},
	{"message_pair_issues", `dataset_id=ANY($1)`}, {"message_pair_dependencies", `dataset_id=ANY($1)`},
	{"missing_indexes", `dataset_id=ANY($1)`}, {"missing_cells", `dataset_id=ANY($1)`},
	{"observation_captures", `dataset_id=ANY($1)`}, {"observation_calls", `dataset_id=ANY($1)`},
	{"observation_participation", `dataset_id=ANY($1)`}, {"observation_header_indexes", `dataset_id=ANY($1)`},
	{"observation_header_rows", `dataset_id=ANY($1)`}, {"runtime_observation_captures", `dataset_id=ANY($1)`},
	{"follow_cursors", `dataset_id=ANY($1)`}, {"follow_batches", `dataset_id=ANY($1)`},
	{"governance_captures", `dataset_id=ANY($1)`}, {"governance_calls", `dataset_id=ANY($1)`},
	{"gov_ops", `dataset_id=ANY($1)`}, {"gov_gaps", `dataset_id=ANY($1)`},
	{"gov_states", `dataset_id=ANY($1)`}, {"gov_proposals", `dataset_id=ANY($1)`},
	{"gov_validator_changes", `dataset_id=ANY($1)`},
	{"input_files", `dataset_id=ANY($1)`},
	{"reexec_runs", `dataset_id=ANY($1)`},
	{"reexec_steps", `run_id IN (SELECT id FROM reexec_runs WHERE dataset_id=ANY($1))`},
	{"reexec_jobs", `dataset_id=ANY($1)`}, {"whatif_runs", `dataset_id=ANY($1)`},
	{"whatif_results", `run_id IN (SELECT id FROM whatif_runs WHERE dataset_id=ANY($1))`},
	{"whatif_jobs", `dataset_id=ANY($1)`},
	{"whatif_network_bindings", `run_id IN (SELECT id FROM whatif_runs WHERE dataset_id=ANY($1))`},
	{"whatif_network_effects", `run_id IN (SELECT id FROM whatif_runs WHERE dataset_id=ANY($1))`},
	{"scenario_sources", `dataset_id=ANY($1)`}, {"scenario_runs", `dataset_id=ANY($1)`},
	{"scenario_seed_results", `run_id IN (SELECT id FROM scenario_runs WHERE dataset_id=ANY($1))`},
	{"scenario_jobs", `dataset_id=ANY($1)`},
}

var exportExcluded = []string{"alert_rules", "alerts", "dataset_deletions", "dataset_storage", "dataset_storage_adoptions", "deployment_scope", "schema_migrations"}

const exportClosureSQL = `WITH RECURSIVE edges(a,b) AS (
 SELECT dataset_id,headers_dataset FROM follow_batches UNION SELECT dataset_id,observations_dataset FROM follow_batches
 UNION SELECT dataset_id,source_id FROM message_pair_dependencies WHERE source_id IS NOT NULL
 UNION SELECT dataset_id,message_id FROM missing_indexes WHERE message_id IS NOT NULL
), ids(id) AS (SELECT $1::bigint UNION SELECT e.b FROM edges e JOIN ids ON e.a=ids.id)
SELECT id FROM ids ORDER BY id`

type exportQuery interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func exportClosure(ctx context.Context, q exportQuery, id int64) ([]int64, error) {
	rows, err := q.Query(ctx, exportClosureSQL, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
		if len(ids) > 10000 {
			return nil, errors.New("export: dependency closure exceeds 10000 datasets")
		}
	}
	return ids, rows.Err()
}

// ExportDataset writes a new private directory and commits manifest.json last.
// An existing output is never replaced. Until that manifest exists a bundle is
// incomplete. Refusal and cancellation remove only files created by this call.
// All selected datasets and required dependencies are fenced against import,
// replay and deletion while a repeatable-read snapshot and retained files copy.
func (s *Store) ExportDataset(ctx context.Context, name, out, target string) (ExportManifest, error) {
	var m ExportManifest
	if name == "" || out == "" || (target != "public" && target != "private") {
		return m, errors.New("export: dataset, output and valid target are required")
	}
	var id int64
	if err := s.pool.QueryRow(ctx, `SELECT id FROM datasets WHERE name=$1`, name).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = ErrNotFound
		}
		return m, err
	}
	ids, err := exportClosure(ctx, s.pool, id)
	if err != nil {
		return m, err
	}
	conn, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		return m, err
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(c)
	}()
	var locked bool
	if err = conn.QueryRow(ctx, `SELECT bool_and(pg_try_advisory_lock(hashtextextended('wbft-analyzer:range:'||current_schema()||':'||id::text,0))) FROM unnest($1::bigint[]) AS id`, ids).Scan(&locked); err != nil {
		return m, err
	}
	if !locked {
		return m, ErrDatasetBusy
	}
	var w *exportWriter
	defer func() {
		if w != nil {
			w.close()
		}
	}()
	err = pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		again, e := exportClosure(ctx, tx, id)
		if e != nil {
			return e
		}
		if !slices.Equal(ids, again) {
			return ErrDatasetBusy
		}
		m = ExportManifest{Schema: "wbft-analyzer-dataset/1", Dataset: id, Datasets: ids, Visibility: "public", Target: target, Tables: []ExportFile{}, Objects: []ExportFile{}, Excluded: slices.Clone(exportExcluded)}
		if e = tx.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&m.SchemaVersion); e != nil {
			return e
		}
		var present int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM datasets WHERE id=ANY($1)`, ids).Scan(&present); e != nil {
			return e
		}
		if present != len(ids) {
			return ErrNotFound
		}
		var private, busy bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM datasets d LEFT JOIN networks n ON n.id=d.network_id WHERE d.id=ANY($1) AND (d.visibility='private' OR n.visibility='private')),
   EXISTS(SELECT 1 FROM datasets WHERE id=ANY($1) AND status IN ('importing','deleting'))
   OR EXISTS(SELECT 1 FROM dataset_deletions WHERE dataset_id=ANY($1))
   OR EXISTS(SELECT 1 FROM dataset_storage_adoptions WHERE dataset_id=ANY($1))
   OR EXISTS(SELECT 1 FROM reexec_jobs WHERE dataset_id=ANY($1) AND status IN ('queued','running'))
   OR EXISTS(SELECT 1 FROM reexec_runs WHERE dataset_id=ANY($1) AND status='running')
   OR EXISTS(SELECT 1 FROM whatif_jobs WHERE dataset_id=ANY($1) AND status IN ('queued','running'))
   OR EXISTS(SELECT 1 FROM whatif_runs WHERE dataset_id=ANY($1) AND status='running')
   OR EXISTS(SELECT 1 FROM scenario_jobs WHERE dataset_id=ANY($1) AND status IN ('queued','running'))
   OR EXISTS(SELECT 1 FROM scenario_runs WHERE dataset_id=ANY($1) AND status='running')`, ids).Scan(&private, &busy); e != nil {
			return e
		}
		if private || privacy.Visibility() == "private" {
			m.Visibility = "private"
		}
		if m.Visibility == "private" && target == "public" {
			return ErrExportPrivate
		}
		if m.Visibility == "private" && privacy.Visibility() != "private" {
			return ErrBuildScope
		}
		if busy {
			return ErrDatasetBusy
		}
		// Fail closed if a migration adds a table without an export ownership rule.
		if e = checkExportCoverage(ctx, tx); e != nil {
			return e
		}
		refs, e := s.exportObjects(ctx, tx, ids)
		if e != nil {
			return e
		}
		w, e = newExportWriter(out)
		if e != nil {
			return e
		}
		for _, ref := range refs {
			if e = ctx.Err(); e != nil {
				return e
			}
			f, e := w.object(ctx, ref)
			if e != nil {
				return e
			}
			if f.Path != "" {
				m.Objects = append(m.Objects, f)
			}
		}
		for _, t := range exportTables {
			f, e := w.table(ctx, tx, t, ids)
			if e != nil {
				return e
			}
			m.Tables = append(m.Tables, f)
		}
		return nil
	})
	if err != nil {
		return ExportManifest{}, err
	}
	if err = ctx.Err(); err != nil {
		return ExportManifest{}, err
	}
	if err = w.commit(m); err != nil {
		return ExportManifest{}, err
	}
	return m, nil
}

func checkExportCoverage(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename`)
	if err != nil {
		return err
	}
	defer rows.Close()
	known := map[string]bool{}
	for _, t := range exportTables {
		known[t.name] = true
	}
	for _, t := range exportExcluded {
		known[t] = true
	}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return err
		}
		if !known[name] {
			return errors.New("export: schema has a table without an ownership rule")
		}
	}
	return rows.Err()
}

func (s *Store) exportObjects(ctx context.Context, tx pgx.Tx, ids []int64) ([]messages.ArchivedFile, error) {
	rows, err := tx.Query(ctx, `SELECT dataset_id,path,sha256,bytes FROM input_files WHERE dataset_id=ANY($1)
 UNION ALL SELECT dataset_id,chain_path,COALESCE(summary->>'chain_sha256',''),NULL::bigint FROM reexec_runs WHERE dataset_id=ANY($1)
 UNION ALL SELECT dataset_id,chain_path,chain_sha256,NULL::bigint FROM whatif_runs WHERE dataset_id=ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	type owned struct {
		id   int64
		file messages.ArchivedFile
	}
	refs := []owned{}
	for rows.Next() {
		var r owned
		var size *int64
		if err = rows.Scan(&r.id, &r.file.Path, &r.file.SHA256, &size); err != nil {
			rows.Close()
			return nil, err
		}
		if size != nil {
			r.file.Bytes = *size
		} else {
			r.file.Bytes = -1
		}
		refs = append(refs, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT dataset_id,snapshot FROM scenario_sources WHERE dataset_id=ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var b []byte
		var snap scenario.SourceSnapshot
		if err = rows.Scan(&id, &b); err != nil {
			break
		}
		if err = json.Unmarshal(b, &snap); err != nil {
			break
		}
		for _, f := range snap.Objects() {
			refs = append(refs, owned{id, f})
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	owner, err := s.StorageOwner(ctx)
	if err != nil {
		return nil, err
	}
	namespaces := map[int64]inputs.Namespace{}
	for _, id := range ids {
		var n inputs.Namespace
		e := tx.QueryRow(ctx, `SELECT root,token,owner FROM dataset_storage WHERE dataset_id=$1`, id).Scan(&n.Root, &n.Token, &n.Owner)
		if errors.Is(e, pgx.ErrNoRows) {
			continue
		}
		if e != nil {
			return nil, e
		}
		if n.Owner != owner {
			return nil, inputs.ErrOwnership
		}
		if e = n.Verify(); e != nil {
			return nil, e
		}
		namespaces[id] = n
	}
	out := []messages.ArchivedFile{}
	for _, r := range refs {
		n, ok := namespaces[r.id]
		if !ok || !ownedPath(n, r.file.Path, r.file.SHA256) {
			return nil, inputs.ErrOwnership
		}
		if r.file.Bytes < 0 {
			info, e := os.Lstat(r.file.Path)
			if e != nil {
				return nil, e
			}
			r.file.Bytes = info.Size()
		}
		out = append(out, r.file)
	}
	slices.SortFunc(out, func(a, b messages.ArchivedFile) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// exportWriter owns only the new directory and its explicitly created files.
// It never recursively removes a caller directory or replaces an existing file.
type exportWriter struct {
	root      *os.Root
	parent    *os.Root
	base      string
	created   []string
	paths     map[string]string
	objects   map[string]ExportFile
	committed bool
}

func newExportWriter(out string) (*exportWriter, error) {
	abs, err := filepath.Abs(out)
	if err != nil {
		return nil, err
	}
	parent, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	base := filepath.Base(abs)
	if err = parent.Mkdir(base, 0700); err != nil {
		parent.Close()
		return nil, err
	}
	root, err := parent.OpenRoot(base)
	if err != nil {
		_ = parent.Remove(base)
		parent.Close()
		return nil, err
	}
	return &exportWriter{root: root, parent: parent, base: base, paths: map[string]string{}, objects: map[string]ExportFile{}}, nil
}
func (w *exportWriter) close() {
	if !w.committed {
		for i := len(w.created) - 1; i >= 0; i-- {
			_ = w.root.Remove(w.created[i])
		}
	}
	_ = w.root.Close()
	if !w.committed {
		_ = w.parent.Remove(w.base)
	}
	_ = w.parent.Close()
}
func (w *exportWriter) create(path string) (*os.File, error) {
	f, err := w.root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		w.created = append(w.created, path)
	}
	return f, err
}
func (w *exportWriter) object(ctx context.Context, ref messages.ArchivedFile) (ExportFile, error) {
	var zero ExportFile
	if !whatifSHA.MatchString(ref.SHA256) || ref.Bytes < 0 || ref.Bytes > 256<<20 {
		return zero, inputs.ErrOwnership
	}
	path := "object-" + ref.SHA256
	old, duplicate := w.objects[ref.SHA256]
	if duplicate && old.Bytes != ref.Bytes {
		return zero, inputs.ErrOwnership
	}
	directory, err := os.OpenRoot(filepath.Dir(ref.Path))
	if err != nil {
		return zero, err
	}
	defer directory.Close()
	info, err := directory.Lstat(filepath.Base(ref.Path))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != ref.Bytes {
		return zero, inputs.ErrOwnership
	}
	src, err := directory.Open(filepath.Base(ref.Path))
	if err != nil {
		return zero, err
	}
	defer src.Close()
	opened, err := src.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return zero, inputs.ErrOwnership
	}
	var dst *os.File
	output := io.Discard
	if !duplicate {
		dst, err = w.create(path)
		if err != nil {
			return zero, err
		}
		defer dst.Close()
		output = dst
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(output, hash), &exportReader{ctx: ctx, r: io.LimitReader(src, ref.Bytes+1)})
	if err != nil {
		return zero, err
	}
	if n != ref.Bytes || hex.EncodeToString(hash.Sum(nil)) != ref.SHA256 {
		return zero, errors.New("export: retained object digest or size changed")
	}
	if duplicate {
		w.paths[ref.Path] = path
		return zero, nil
	}
	if err = dst.Sync(); err != nil {
		return zero, err
	}
	f := ExportFile{Path: path, SHA256: ref.SHA256, Bytes: n}
	w.objects[ref.SHA256] = f
	w.paths[ref.Path] = path
	return f, nil
}

type exportReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *exportReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}

func (w *exportWriter) table(ctx context.Context, tx pgx.Tx, t exportTable, ids []int64) (ExportFile, error) {
	result := ExportFile{Path: t.name + ".jsonl"}
	dst, err := w.create(result.Path)
	if err != nil {
		return result, err
	}
	defer dst.Close()
	h := sha256.New()
	counter := &exportCounter{w: io.MultiWriter(dst, h)}
	// JSONB's stable textual ordering avoids converting numeric(156,0) through a float.
	rows, err := tx.Query(ctx, `SELECT to_jsonb(t) FROM `+pgx.Identifier{t.name}.Sanitize()+` t WHERE `+t.where+` ORDER BY to_jsonb(t)::text`, ids)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return result, err
		}
		var row map[string]json.RawMessage
		if err = json.Unmarshal(b, &row); err != nil {
			return result, err
		}
		switch t.name {
		case "input_files":
			var path string
			if err = json.Unmarshal(row["path"], &path); err != nil {
				return result, err
			}
			p, ok := w.paths[path]
			if !ok {
				return result, inputs.ErrOwnership
			}
			row["path"], _ = json.Marshal(p)
		case "reexec_runs", "whatif_runs":
			var path string
			if err = json.Unmarshal(row["chain_path"], &path); err != nil {
				return result, err
			}
			p, ok := w.paths[path]
			if !ok {
				return result, inputs.ErrOwnership
			}
			row["chain_path"], _ = json.Marshal(p)
		case "scenario_sources":
			var snap scenario.SourceSnapshot
			if err = json.Unmarshal(row["snapshot"], &snap); err != nil {
				return result, err
			}
			for _, f := range snap.Objects() {
				if w.paths[f.Path] == "" {
					return result, inputs.ErrOwnership
				}
			}
			snap = snap.Rebase(".")
			raw, err := json.Marshal(snap)
			if err != nil {
				return result, err
			}
			var generic any
			decoder := json.NewDecoder(strings.NewReader(string(raw)))
			decoder.UseNumber()
			if err = decoder.Decode(&generic); err != nil {
				return result, err
			}
			prefixSnapshotObjects(generic)
			row["snapshot"], _ = json.Marshal(generic)
		}
		if err = json.NewEncoder(counter).Encode(row); err != nil {
			return result, err
		}
		result.Rows++
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if err = dst.Sync(); err != nil {
		return result, err
	}
	result.Bytes = counter.n
	result.SHA256 = hex.EncodeToString(h.Sum(nil))
	return result, nil
}
func prefixSnapshotObjects(v any) {
	switch x := v.(type) {
	case map[string]any:
		if sha, ok := x["SHA256"].(string); ok {
			if _, ok = x["Path"]; ok {
				x["Path"] = "object-" + sha
			}
		}
		for _, v := range x {
			prefixSnapshotObjects(v)
		}
	case []any:
		for _, v := range x {
			prefixSnapshotObjects(v)
		}
	}
}

type exportCounter struct {
	w io.Writer
	n int64
}

func (w *exportCounter) Write(b []byte) (int, error) {
	n, e := w.w.Write(b)
	w.n += int64(n)
	return n, e
}
func (w *exportWriter) commit(m ExportManifest) error {
	f, err := w.create(".manifest.pending")
	if err != nil {
		return err
	}
	err = json.NewEncoder(f).Encode(m)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = w.root.Link(".manifest.pending", "manifest.json"); err != nil {
		return err
	}
	w.created = append(w.created, "manifest.json")
	if err = w.root.Remove(".manifest.pending"); err != nil {
		return err
	}
	dir, err := w.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return fmt.Errorf("export: sync bundle: %w", err)
	}
	w.committed = true
	return nil
}
