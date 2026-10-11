package ingest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/jackc/pgx/v5"
)

// testStore opens a migrated store on a schema of its own
// (WBFT_ANALYZER_TEST_DSN), dropped when the test ends.
func testStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("WBFT_ANALYZER_TEST_DSN")
	if dsn == "" {
		t.Skip("WBFT_ANALYZER_TEST_DSN is not set")
	}
	ctx := context.Background()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	schema := "t_" + hex.EncodeToString(b)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = conn.Close(context.Background())
	})
	u, _ := url.Parse(dsn)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	s, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

// writeReport writes the sample report of internal/reports changed by f.
func writeReport(t *testing.T, dir, name string, f func(map[string]any)) string {
	t.Helper()
	b, err := os.ReadFile("../reports/testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if f != nil {
		f(m)
	}
	out, _ := json.Marshal(m)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// onNetwork makes report i of a network with blocks 100*i+1 .. 100*i+100
// and count observations of kind late_seal.
func onNetwork(i int, count int64) func(map[string]any) {
	return func(m map[string]any) {
		run := m["run"].(map[string]any)
		run["id"] = fmt.Sprintf("run-%02d", i)
		run["finished_at"] = fmt.Sprintf("2026-10-12T00:%02d:00Z", i)
		run["network"] = map[string]any{"name": "testnet", "chain_id": 8282, "genesis_hash": "0x" + fmt.Sprintf("%064x", 1)}
		run["range"] = map[string]any{"from": 100*i + 1, "to": 100*i + 100}
		m["observations"] = []any{map[string]any{"id": "o1", "kind": "late_seal", "imp": []any{}, "checker": "c", "count": count,
			"evidence": []any{}, "requirements": []any{"WBFT-SM-083"}}}
	}
}

// TestReports: reports are stored once; refused and invalid files are
// recorded and skipped.
func TestReports(t *testing.T) {
	s := testStore(t)
	dir := t.TempDir()
	good := writeReport(t, dir, "good.json", nil)
	refused := writeReport(t, dir, "refused.json", func(m map[string]any) {
		m["run"].(map[string]any)["inspector"].(map[string]any)["build"] = "internal"
	})
	invalid := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalid, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &Reporter{Store: s}
	res, err := r.Files(context.Background(), []string{good, good, refused, invalid, filepath.Join(dir, "missing.json")})
	if err != nil {
		t.Fatal(err)
	}
	want := []Outcome{Added, Skipped, Refused, Invalid, Invalid}
	for i, x := range res {
		if x.Outcome != want[i] {
			t.Errorf("%s: %s (%s), want %s", filepath.Base(x.File), x.Outcome, x.Detail, want[i])
		}
	}
	if n, o, err := s.ReportCounts(context.Background(), res[0].ID); err != nil || n == 0 || o != 0 {
		t.Fatalf("stored report: %d results, %d observations, %v", n, o, err)
	}
}

// TestAlerts: ten reports on one network with a rising count of an
// observation fire a relative rule and tell its webhook; reports with the
// count back down resolve it (A0 exit criterion, end to end).
func TestAlerts(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var mu sync.Mutex
	var got []Alert
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		var a Alert
		if err := json.Unmarshal(b, &a); err == nil {
			mu.Lock()
			got = append(got, a)
			mu.Unlock()
		}
	}))
	defer hook.Close()
	dir := t.TempDir()
	r := &Reporter{Store: s, HTTP: hook.Client()}
	load := func(i int, count int64) Result {
		t.Helper()
		res, err := r.Files(ctx, []string{writeReport(t, dir, fmt.Sprintf("r%02d.json", i), onNetwork(i, count))})
		if err != nil || len(res) != 1 || res[0].Outcome != Added {
			t.Fatalf("report %d: %+v %v", i, res, err)
		}
		return res[0]
	}
	// The first report creates the network; then the rule is added.
	load(0, 2)
	rules, err := s.AlertRules(ctx, 1)
	if err != nil || len(rules) != 0 {
		t.Fatalf("rules %v %v", rules, err)
	}
	if _, err := s.AddAlertRule(ctx, store.AlertRule{NetworkID: 1, Kind: "late_seal", Window: 3, Baseline: 5, Mode: "relative",
		Threshold: 2, Webhook: hook.URL}); err != nil {
		t.Fatal(err)
	}
	var changes []string
	counts := []int64{2, 3, 2, 2, 3, 5, 8, 9, 10, 2, 2, 2}
	for i, c := range counts {
		for _, a := range load(i+1, c).Alerts {
			changes = append(changes, fmt.Sprintf("%d:%s->%s", i+1, a.Before, a.State))
		}
	}
	// The report loaded before the rule counts too: at report 7 there are
	// eight points, recent median 0.05 against a baseline of 0.02 (x2);
	// at report 11 the recent median 0.02 is below twice the baseline 0.05.
	want := "[1:->pending 7:pending->firing 11:firing->resolved]"
	if fmt.Sprint(changes) != want {
		t.Fatalf("changes %v, want %s", changes, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 || got[1].State != "firing" || got[1].Kind != "late_seal" || got[1].Recent != 0.05 || got[2].State != "resolved" {
		t.Fatalf("webhook calls %+v", got)
	}
}
