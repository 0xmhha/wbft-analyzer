package reports

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// sample is a report of wbft-inspector c59b1c5 on one of its event fixtures.
func sample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// edit changes the sample report as a generic JSON value.
func edit(t *testing.T, f func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(sample(t), &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func run(m map[string]any) map[string]any       { return m["run"].(map[string]any) }
func inspector(m map[string]any) map[string]any { return run(m)["inspector"].(map[string]any) }

// TestSample: the sample parses, its ID is the file's sha256, and it is
// admitted.
func TestSample(t *testing.T) {
	raw := sample(t)
	r, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if r.ID != hex.EncodeToString(sum[:]) || len(r.Results) == 0 || r.Run.Inspector.Build != "public" {
		t.Fatalf("report %s: %d results, build %q", r.ID, len(r.Results), r.Run.Inspector.Build)
	}
	if err := Admit(r); err != nil {
		t.Fatal(err)
	}
}

// TestRefused: each public-build check refuses the whole report, and the
// error names no requirement ID.
func TestRefused(t *testing.T) {
	const withheld = "WBFT-SM-999"
	for _, c := range []struct {
		name string
		f    func(map[string]any)
		why  string
	}{
		{"private build", func(m map[string]any) { inspector(m)["build"] = "internal" }, "not public"},
		{"result outside the list", func(m map[string]any) {
			m["results"].([]any)[0].(map[string]any)["requirement"] = withheld
		}, "a result names a requirement"},
		{"observation outside the list", func(m map[string]any) {
			m["observations"] = []any{map[string]any{"id": "o1", "kind": "k", "imp": []any{}, "checker": "c", "count": 1,
				"evidence": []any{}, "requirements": []any{"WBFT-SM-001", withheld}}}
		}, "an observation names a requirement"},
		{"unknown catalog", func(m map[string]any) { inspector(m)["catalog_sha256"] = strings.Repeat("0", 64) }, "catalog hash"},
	} {
		r, err := Parse(edit(t, c.f))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		err = Admit(r)
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), c.why) || strings.Contains(err.Error(), withheld) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestFormat: a file that is not a report of the schema is rejected.
func TestFormat(t *testing.T) {
	for _, c := range []struct {
		name string
		raw  []byte
	}{
		{"other schema", edit(t, func(m map[string]any) { m["schema"] = "wbft-inspector-report/2" })},
		{"no run id", edit(t, func(m map[string]any) { delete(run(m), "id") })},
		{"no results", edit(t, func(m map[string]any) { delete(m, "results") })},
		{"result without verdict", edit(t, func(m map[string]any) { delete(m["results"].([]any)[0].(map[string]any), "verdict") })},
		{"data after the report", append(sample(t), []byte(`{}`)...)},
		{"not JSON", []byte("not json")},
	} {
		if _, err := Parse(c.raw); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
