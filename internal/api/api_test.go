package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
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

// report returns the sample report of internal/reports changed by f.
func report(t *testing.T, f func(map[string]any)) []byte {
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
	return out
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

// client calls a handler as a loopback client.
type client struct {
	t *testing.T
	h http.Handler
}

// do sends a request (body JSON when not nil) and decodes the answer into
// out when out is not nil.
func (c client) do(method, path string, body []byte, out any) int {
	c.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Host = "127.0.0.1:8080"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			c.t.Fatalf("%s %s: %d %q: %v", method, path, rec.Code, rec.Body, err)
		}
	}
	return rec.Code
}

// TestReports: a report posted to the API is loaded like a file given to
// "ingest reports"; the stored reports, results and observations are
// read back; refused, invalid and oversized bodies are answered without
// storing anything, and a refusal names no requirement.
func TestReports(t *testing.T) {
	s := testStore(t)
	c := client{t, (&Server{Store: s, Reporter: &ingest.Reporter{Store: s}, MaxBody: 1 << 20}).Handler()}

	var lr LoadResult
	if code := c.do("POST", "/v1/reports", report(t, onNetwork(1, 3)), &lr); code != 201 || lr.Outcome != ingest.Added || len(lr.ID) != 64 {
		t.Fatalf("post: %d %+v", code, lr)
	}
	id := lr.ID
	if code := c.do("POST", "/v1/reports", report(t, onNetwork(1, 3)), &lr); code != 200 || lr.Outcome != ingest.Skipped {
		t.Fatalf("post again: %d %+v", code, lr)
	}
	refused := report(t, func(m map[string]any) {
		m["results"].([]any)[0].(map[string]any)["requirement"] = "WBFT-ZZZ-999"
	})
	var raw json.RawMessage
	if code := c.do("POST", "/v1/reports", refused, &raw); code != 422 || !strings.Contains(string(raw), `"refused"`) ||
		strings.Contains(string(raw), "ZZZ") {
		t.Fatalf("refused: %d %s", code, raw)
	}
	if code := c.do("POST", "/v1/reports", []byte(`{"schema":"x"}`), &lr); code != 422 || lr.Outcome != ingest.Invalid {
		t.Fatalf("invalid: %d %+v", code, lr)
	}
	if code := c.do("POST", "/v1/reports", bytes.Repeat([]byte(" "), 2<<20), &raw); code != 413 {
		t.Fatalf("too large: %d %s", code, raw)
	}

	var list struct{ Reports []Report }
	if code := c.do("GET", "/v1/reports", nil, &list); code != 200 || len(list.Reports) != 1 || list.Reports[0].ID != id {
		t.Fatalf("reports: %d %+v", code, list)
	}
	if n := list.Reports[0].NetworkID; n == nil || *n != 1 || list.Reports[0].RunID != "run-01" {
		t.Fatalf("report: %+v", list.Reports[0])
	}
	if code := c.do("GET", "/v1/reports?net=2", nil, &list); code != 200 || len(list.Reports) != 0 {
		t.Fatalf("reports of network 2: %d %+v", code, list)
	}
	var one Report
	if code := c.do("GET", "/v1/reports/"+id, nil, &one); code != 200 || one.ID != id || !bytes.Contains(one.Range, []byte(`"from"`)) {
		t.Fatalf("report: %d %+v", code, one)
	}
	if code := c.do("GET", "/v1/reports/"+strings.Repeat("0", 64), nil, &raw); code != 404 {
		t.Fatalf("missing report: %d", code)
	}
	if code := c.do("GET", "/v1/reports/NOTHEX", nil, &raw); code != 400 {
		t.Fatalf("bad report ID: %d", code)
	}

	var res struct{ Results []Result }
	if code := c.do("GET", "/v1/reports/"+id+"/results", nil, &res); code != 200 || len(res.Results) != 87 {
		t.Fatalf("results: %d %d", code, len(res.Results))
	}
	if code := c.do("GET", "/v1/reports/"+id+"/results?verdict=PASS&node=", nil, &res); code != 200 || len(res.Results) == 0 {
		t.Fatalf("PASS results: %d %d", code, len(res.Results))
	}
	for _, r := range res.Results {
		if r.Verdict != "PASS" || r.Node != "" {
			t.Fatalf("filtered result %+v", r)
		}
	}
	if code := c.do("GET", "/v1/reports/"+id+"/results?node=0xabc", nil, &res); code != 200 || len(res.Results) != 0 {
		t.Fatalf("results of an unknown node: %d %d", code, len(res.Results))
	}
	var obs struct{ Observations []Observation }
	if code := c.do("GET", "/v1/reports/"+id+"/observations", nil, &obs); code != 200 || len(obs.Observations) != 1 ||
		obs.Observations[0].Kind != "late_seal" || obs.Observations[0].Count != 3 {
		t.Fatalf("observations: %d %+v", code, obs)
	}

	var nets struct{ Networks []Network }
	if code := c.do("GET", "/v1/networks", nil, &nets); code != 200 || len(nets.Networks) != 1 ||
		nets.Networks[0].ChainID != "8282" || nets.Networks[0].Reports != 1 {
		t.Fatalf("networks: %d %+v", code, nets)
	}
	for path, want := range map[string]int{"/v1/networks/1": 200, "/v1/networks/9": 404, "/v1/networks/x": 400, "/v1/networks/0": 400,
		"/v1/reports?net=x": 400, "/v1/nothing": 404} {
		if code := c.do("GET", path, nil, &raw); code != want {
			t.Errorf("%s: %d, want %d", path, code, want)
		}
	}
}

// TestTrendsAndAlerts: trend points are read in a time window that must
// be given; alert rules are replaced as a set, a rule left unchanged keeps
// its ID and state, and posted reports move the states read from
// /v1/alerts.
func TestTrendsAndAlerts(t *testing.T) {
	s := testStore(t)
	c := client{t, (&Server{Store: s, Reporter: &ingest.Reporter{Store: s}}).Handler()}
	var lr LoadResult
	post := func(i int, count int64) LoadResult {
		t.Helper()
		if code := c.do("POST", "/v1/reports", report(t, onNetwork(i, count)), &lr); code != 201 {
			t.Fatalf("report %d: %d %+v", i, code, lr)
		}
		return lr
	}
	for i, n := range []int64{1, 2, 3, 4} {
		post(i+1, n)
	}

	var raw json.RawMessage
	if code := c.do("GET", "/v1/networks/1/trends/observations?kind=late_seal", nil, &raw); code != 400 {
		t.Fatalf("no window: %d", code)
	}
	if code := c.do("GET", "/v1/networks/1/trends/observations?kind=late_seal&from_t=yesterday&to_t=now", nil, &raw); code != 400 {
		t.Fatalf("bad window: %d", code)
	}
	var pts struct{ Points []TrendPoint }
	q := "/v1/networks/1/trends/observations?kind=late_seal&from_t=2026-10-12T00:02:00Z&to_t=2026-10-12T00:03:00Z"
	if code := c.do("GET", q, nil, &pts); code != 200 || len(pts.Points) != 2 || pts.Points[0].Rate != 0.02 || pts.Points[1].Rate != 0.03 {
		t.Fatalf("points: %d %+v", code, pts)
	}

	put := func(body string, out any) int {
		t.Helper()
		return c.do("PUT", "/v1/networks/1/alert-rules", []byte(body), out)
	}
	for _, bad := range []string{
		`{}`,
		`{"rules": [{"kind": "late_seal", "window": 2, "mode": "sometimes", "threshold": 1}]}`,
		`{"rules": [{"kind": "late_seal", "window": 0, "mode": "absolute", "threshold": 1}]}`,
		`{"rules": [{"kind": "late_seal", "window": 2, "mode": "relative", "threshold": 1}]}`,
		`{"rules": [{"kind": "late_seal", "window": 2, "mode": "absolute", "threshold": 1, "webhook": "file:///etc/passwd"}]}`,
		`{"rules": [{"kind": "late_seal", "window": 2, "mode": "absolute", "threshold": 1, "webhook": "http://u:p@host/"}]}`,
		`{"rules": [{"kind": "late_seal", "window": 2, "mode": "absolute", "threshold": 1, "extra": true}]}`,
	} {
		if code := put(bad, &raw); code != 400 {
			t.Errorf("%s: %d %s", bad, code, raw)
		}
	}
	var rules struct{ Rules []AlertRule }
	const absolute = `{"kind": "late_seal", "window": 2, "mode": "absolute", "threshold": 0.03}`
	if code := put(`{"rules": [`+absolute+`]}`, &rules); code != 200 || len(rules.Rules) != 1 {
		t.Fatalf("put: %d %+v", code, rules)
	}
	kept := rules.Rules[0].ID
	// The next report evaluates the rule: median of 0.04, 0.05 > 0.03.
	if a := post(5, 5).Alerts; len(a) != 1 || a[0].State != "firing" {
		t.Fatalf("alerts after report 5: %+v", a)
	}
	const relative = `{"kind": "late_seal", "window": 1, "baseline": 3, "mode": "relative", "threshold": 2, "webhook": "http://127.0.0.1:1/hook"}`
	if code := put(`{"rules": [`+absolute+`, `+relative+`]}`, &rules); code != 200 || len(rules.Rules) != 2 || rules.Rules[0].ID != kept {
		t.Fatalf("put again: %d %+v", code, rules)
	}
	var alerts struct{ Alerts []Alert }
	if code := c.do("GET", "/v1/alerts?net=1", nil, &alerts); code != 200 || len(alerts.Alerts) != 1 ||
		alerts.Alerts[0].Rule.ID != kept || alerts.Alerts[0].State != "firing" || math.Abs(alerts.Alerts[0].Recent-0.045) > 1e-12 {
		t.Fatalf("alerts: %d %+v", code, alerts)
	}
	// Both rules are evaluated: the absolute one stays firing (median of
	// 0.05, 0.09), the relative one fires (0.09 > 2 x 0.04); its webhook
	// cannot be reached, which does not fail the load.
	if a := post(6, 9).Alerts; len(a) != 1 || a[0].Rule == kept || a[0].State != "firing" || a[0].WebhookError == "" {
		t.Fatalf("alerts after report 6: %+v", a)
	}
	if code := c.do("GET", "/v1/alerts", nil, &alerts); code != 200 || len(alerts.Alerts) != 2 ||
		alerts.Alerts[0].State != "firing" || alerts.Alerts[1].State != "firing" || alerts.Alerts[1].Baseline != 0.04 {
		t.Fatalf("alerts: %d %+v", code, alerts)
	}
	if code := put(`{"rules": []}`, &rules); code != 200 || len(rules.Rules) != 0 {
		t.Fatalf("clear: %d %+v", code, rules)
	}
	if code := c.do("GET", "/v1/alerts", nil, &alerts); code != 200 || len(alerts.Alerts) != 0 {
		t.Fatalf("alerts after clear: %d %+v", code, alerts)
	}
	if code := c.do("PUT", "/v1/networks/9/alert-rules", []byte(`{"rules": []}`), &raw); code != 404 {
		t.Fatalf("rules of a missing network: %d", code)
	}
}
