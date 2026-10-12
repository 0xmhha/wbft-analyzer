package api

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite api/openapi.json")

// committed is the document kept for the front end's type generation.
const committed = "../../api/openapi.json"

// TestOpenAPIDocument: the committed document is the one the code builds
// (go test ./internal/api -run TestOpenAPIDocument -update rewrites it),
// and the server answers it.
func TestOpenAPIDocument(t *testing.T) {
	doc, err := Document()
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(committed, doc, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	have, err := os.ReadFile(committed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(have, doc) {
		t.Fatalf("%s is stale; run: go test ./internal/api -run TestOpenAPIDocument -update", committed)
	}
	req := httptest.NewRequest("GET", openAPIPath, nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	(&Server{}).Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), doc) {
		t.Fatalf("GET %s: %d", openAPIPath, rec.Code)
	}
	var d struct {
		Paths map[string]map[string]any
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{openAPIPath: true}
	for _, rt := range routes {
		want[rt.path] = true
	}
	if len(d.Paths) != len(want) {
		t.Errorf("%d paths, want %d", len(d.Paths), len(want))
	}
}

// spec is the OpenAPI document decoded for checking answers against it.
type spec struct {
	Paths      map[string]map[string]operation `json:"paths"`
	Components struct {
		Schemas map[string]map[string]any `json:"schemas"`
	} `json:"components"`
}

type operation struct {
	Responses map[string]struct {
		Content map[string]struct {
			Schema map[string]any `json:"schema"`
		} `json:"content"`
	} `json:"responses"`
}

func loadSpec(t *testing.T) *spec {
	t.Helper()
	doc, err := Document()
	if err != nil {
		t.Fatal(err)
	}
	var s spec
	if err := json.Unmarshal(doc, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

// answerSchema returns the schema of an answer: the operation is found by
// matching the request path against the document's path templates.
func (s *spec) answerSchema(method, path string, code int) (map[string]any, error) {
	path, _, _ = strings.Cut(path, "?")
	for tmpl, ops := range s.Paths {
		if !matchPath(tmpl, path) {
			continue
		}
		op, ok := ops[strings.ToLower(method)]
		if !ok {
			continue
		}
		key := strconv.Itoa(code)
		r, ok := op.Responses[key]
		if !ok {
			r, ok = op.Responses[key[:1]+"XX"]
		}
		if !ok {
			return nil, fmt.Errorf("%s %s: the document has no answer %d", method, tmpl, code)
		}
		return r.Content["application/json"].Schema, nil
	}
	if code == 404 || code == 405 {
		return map[string]any{"$ref": "#/components/schemas/Error"}, nil
	}
	return nil, fmt.Errorf("%s %s: not in the document", method, path)
}

func matchPath(tmpl, path string) bool {
	a, b := strings.Split(tmpl, "/"), strings.Split(path, "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.HasPrefix(a[i], "{") && a[i] != b[i] {
			return false
		}
	}
	return true
}

// check reports where v does not match the schema: the JSON Schema
// subset Document writes ($ref, type, properties, required,
// additionalProperties, items, anyOf, enum).
func (s *spec) check(v any, sch map[string]any, at string) error {
	if ref, ok := sch["$ref"].(string); ok {
		return s.check(v, s.Components.Schemas[strings.TrimPrefix(ref, "#/components/schemas/")], at)
	}
	if alts, ok := sch["anyOf"].([]any); ok {
		for _, a := range alts {
			if s.check(v, a.(map[string]any), at) == nil {
				return nil
			}
		}
		return fmt.Errorf("%s: %v matches no alternative", at, v)
	}
	if e, ok := sch["enum"].([]any); ok && !slices.Contains(e, v) {
		return fmt.Errorf("%s: %v is not one of %v", at, v, e)
	}
	var types []string
	switch t := sch["type"].(type) {
	case string:
		types = []string{t}
	case []any:
		for _, x := range t {
			types = append(types, x.(string))
		}
	case nil:
		return nil // any value
	}
	// An integer is a number too.
	jt := jsonType(v)
	if !slices.Contains(types, jt) && (jt != "integer" || !slices.Contains(types, "number")) {
		return fmt.Errorf("%s: %s, want %v", at, jt, types)
	}
	switch v := v.(type) {
	case map[string]any:
		props, _ := sch["properties"].(map[string]any)
		for _, r := range sch["required"].([]any) {
			if _, ok := v[r.(string)]; !ok {
				return fmt.Errorf("%s: %q is missing", at, r)
			}
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p, ok := props[k]
			if !ok {
				if extra, allowed := sch["additionalProperties"].(map[string]any); allowed {
					p = extra
				} else {
					return fmt.Errorf("%s: %q is not in the document", at, k)
				}
			}
			if err := s.check(v[k], p.(map[string]any), at+"."+k); err != nil {
				return err
			}
		}
	case []any:
		for i, x := range v {
			if err := s.check(x, sch["items"].(map[string]any), fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func jsonType(v any) string {
	switch v := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		if _, err := v.Int64(); err == nil {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

// TestCheck: the answer check itself finds a missing field, an extra
// field, a wrong type and a value outside an enum.
func TestCheck(t *testing.T) {
	s := loadSpec(t)
	sch := map[string]any{"$ref": "#/components/schemas/AlertRule"}
	good := `{"id": 1, "kind": "k", "node": "", "window": 1, "baseline": 0, "mode": "absolute", "threshold": 0.5, "webhook": ""}`
	for body, ok := range map[string]bool{
		good: true,
		`{"kind": "k", "node": "", "window": 1, "baseline": 0, "mode": "absolute", "threshold": 1, "webhook": ""}`:         true,
		`{"kind": "k", "node": "", "window": 1, "baseline": 0, "mode": "absolute", "threshold": 1}`:                        false,
		`{"kind": "k", "node": "", "window": 1, "baseline": 0, "mode": "absolute", "threshold": 1, "webhook": "", "x": 1}`: false,
		`{"kind": "k", "node": "", "window": 1.5, "baseline": 0, "mode": "absolute", "threshold": 1, "webhook": ""}`:       false,
		`{"kind": "k", "node": "", "window": 1, "baseline": 0, "mode": "sometimes", "threshold": 1, "webhook": ""}`:        false,
		`{"kind": null, "node": "", "window": 1, "baseline": 0, "mode": "absolute", "threshold": 1, "webhook": ""}`:        false,
	} {
		d := json.NewDecoder(strings.NewReader(body))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
		if err := s.check(v, sch, "$"); (err == nil) != ok {
			t.Errorf("%s: %v, want ok %v", body, err, ok)
		}
	}
}
