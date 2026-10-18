package api

import (
	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"testing"
)

// Stored report classification must survive both list and detail reads, even
// when a report has no network. It is distinct from its original verdicts.
func TestReportClassification(t *testing.T) {
	for _, networked := range []bool{true, false} {
		name := "networkless"
		if networked {
			name = "networked"
		}
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			c := client{t, (&Server{Store: s, Reporter: &ingest.Reporter{Store: s}}).Handler()}
			var loaded LoadResult
			raw := report(t, func(m map[string]any) {
				onNetwork(1, 3)(m)
				if !networked {
					delete(m["run"].(map[string]any), "network")
				}
			})
			if status := c.do("POST", "/v1/reports", raw, &loaded); status != 201 {
				t.Fatalf("post: %d", status)
			}
			check := func(r map[string]any) {
				t.Helper()
				if r["id"] != loaded.ID || r["inspector_build"] != "public" || r["visibility"] != "public" {
					t.Fatalf("stored classification missing: id=%v build=%v visibility=%v", r["id"], r["inspector_build"], r["visibility"])
				}
			}
			var list struct {
				Reports []map[string]any `json:"reports"`
			}
			if status := c.do("GET", "/v1/reports", nil, &list); status != 200 || len(list.Reports) != 1 {
				t.Fatalf("list: %d", status)
			}
			check(list.Reports[0])
			var one map[string]any
			if status := c.do("GET", "/v1/reports/"+loaded.ID, nil, &one); status != 200 {
				t.Fatalf("detail: %d", status)
			}
			check(one)
			if !networked && one["network_id"] != nil {
				t.Fatal("networkless report gained a network")
			}
		})
	}
}
