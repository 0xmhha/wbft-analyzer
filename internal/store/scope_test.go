package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestReportDatasetOwnership(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	r := report(strings.Repeat("d", 64))
	if _, _, err := s.PutReport(ctx, r); err != nil {
		t.Fatal(err)
	}
	var name, scope, build string
	if err := s.pool.QueryRow(ctx, `SELECT d.name,d.visibility,r.inspector_build FROM reports r JOIN datasets d ON d.id=r.dataset_id WHERE r.id=$1`, r.ID).Scan(&name, &scope, &build); err != nil {
		t.Fatal(err)
	}
	if name != "report:"+r.ID || scope != "public" || build != "public" {
		t.Fatal("report ownership/classification missing")
	}
	if _, err := s.pool.Exec(ctx, `UPDATE deployment_scope SET visibility='private'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(ctx); !errors.Is(err, ErrBuildScope) {
		t.Fatalf("public build entered private deployment: %v", err)
	}
	cfg := s.pool.Config().ConnString()
	if other, err := Open(ctx, cfg); !errors.Is(err, ErrBuildScope) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("public open: %v", err)
	}
}

func TestReportOwnershipMigrationPreservesRows(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, `CREATE TABLE schema_migrations(version integer PRIMARY KEY,name text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations[:27] {
		if _, err = s.pool.Exec(ctx, m.sql); err != nil {
			t.Fatal(err)
		}
		if _, err = s.pool.Exec(ctx, `INSERT INTO schema_migrations(version,name) VALUES($1,$2)`, m.version, m.name); err != nil {
			t.Fatal(err)
		}
	}
	id := strings.Repeat("c", 64)
	if _, err = s.pool.Exec(ctx, `INSERT INTO reports(id,run_id,started_at,finished_at,inspector_version,inspector_commit,catalog_sha256,spec_commit,summary) VALUES($1,'legacy','start','finish','version','commit','catalog','spec','{"unchanged":true}');`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, `INSERT INTO results(report_id,requirement,verdict,coverage) VALUES($1,'WBFT-SM-083','CANNOT_DECIDE','{"instances":2}')`, id); err != nil {
		t.Fatal(err)
	}
	var before, after []byte
	query := `SELECT jsonb_build_object('report',to_jsonb(r)-'dataset_id'-'inspector_build','results',(SELECT jsonb_agg(to_jsonb(x)) FROM results x WHERE report_id=r.id)) FROM reports r WHERE id=$1`
	if err = s.pool.QueryRow(ctx, query, id).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.pool.QueryRow(ctx, query, id).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("migration rewrote legacy results")
	}
	var name string
	if err = s.pool.QueryRow(ctx, `SELECT d.name FROM reports r JOIN datasets d ON d.id=r.dataset_id WHERE r.id=$1`, id).Scan(&name); err != nil || name != "report:"+id {
		t.Fatal("legacy ownership missing", err)
	}
}
