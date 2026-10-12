package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// openAPIPath is where the server answers the OpenAPI document.
const openAPIPath = "/v1/openapi.json"

// Document returns the OpenAPI 3.1 document of the API, built from the
// route table and the Go types of the answers (design.md 8.1): the front
// end's types are generated from it. The output is stable (sorted keys)
// and ends with a newline.
func Document() ([]byte, error) {
	g := &schemas{components: map[string]any{}, names: map[reflect.Type]string{}}
	paths := map[string]map[string]any{}
	for _, rt := range routes {
		op := map[string]any{"operationId": rt.id, "summary": rt.summary}
		if len(rt.params) > 0 {
			var ps []any
			for _, p := range rt.params {
				sch := map[string]any{"type": p.typ}
				if p.format != "" {
					sch["format"] = p.format
				}
				ps = append(ps, map[string]any{"name": p.name, "in": p.in, "description": p.doc, "required": p.required, "schema": sch})
			}
			op["parameters"] = ps
		}
		switch {
		case rt.body != nil:
			op["requestBody"] = jsonContent(g.of(reflect.TypeOf(rt.body)), true)
		case rt.rawBody != "":
			op["requestBody"] = jsonContent(map[string]any{"type": "object", "description": rt.rawBody}, true)
		}
		answers := map[string]any{}
		for code, v := range rt.answers {
			a := jsonContent(g.of(reflect.TypeOf(v)), false)
			a["description"] = http.StatusText(code)
			answers[strconv.Itoa(code)] = a
		}
		op["responses"] = failures(g, answers)
		if paths[rt.path] == nil {
			paths[rt.path] = map[string]any{}
		}
		paths[rt.path][strings.ToLower(rt.method)] = op
	}
	doc := jsonContent(map[string]any{"type": "object"}, false)
	doc["description"] = "OK"
	paths[openAPIPath] = map[string]any{"get": map[string]any{
		"operationId": "getOpenAPI", "summary": "This document.", "responses": failures(g, map[string]any{"200": doc}),
	}}
	out := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "wbft-analyzer",
			"version": "v1",
			"license": map[string]any{"name": "LGPL-3.0-or-later", "identifier": "LGPL-3.0-or-later"},
			"description": "Networks, datasets, WBFT headers and epochs, inspector reports, observation trends and alerts. Without a token the server answers " +
				"only to loopback host names; with one, every request carries it as a bearer token. Writes are JSON.",
		},
		"servers":  []any{map[string]any{"url": "/"}},
		"security": []any{map[string]any{}, map[string]any{"bearer": []any{}}},
		"paths":    paths,
		"components": map[string]any{
			"schemas":         g.components,
			"securitySchemes": map[string]any{"bearer": map[string]any{"type": "http", "scheme": "bearer"}},
		},
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// failures adds the answers every operation can give: 4XX and 5XX with
// Error.
func failures(g *schemas, answers map[string]any) map[string]any {
	ref := g.of(reflect.TypeOf(Error{}))
	for _, c := range []string{"4XX", "5XX"} {
		a := jsonContent(ref, false)
		a["description"] = "the request failed"
		answers[c] = a
	}
	return answers
}

func jsonContent(schema map[string]any, required bool) map[string]any {
	c := map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	if required {
		c["required"] = true
	}
	return c
}

// schemas turns Go types into JSON Schema: structs become components
// referenced by name.
type schemas struct {
	components map[string]any
	names      map[reflect.Type]string
}

var (
	timeType = reflect.TypeOf(time.Time{})
	rawType  = reflect.TypeOf(json.RawMessage(nil))
)

// of returns the schema of t, adding the components it needs.
func (g *schemas) of(t reflect.Type) map[string]any {
	switch t {
	case timeType:
		return map[string]any{"type": "string", "format": "date-time"}
	case rawType:
		return map[string]any{"description": "a JSON value admitted by the source or report reader"}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return nullable(g.of(t.Elem()))
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer", "format": "int64"}
	case reflect.Float64:
		return map[string]any{"type": "number", "format": "double"}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": g.of(t.Elem())}
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			panic(fmt.Sprintf("api: unsupported map key %s", t))
		}
		return map[string]any{"type": "object", "properties": map[string]any{}, "required": []string{}, "additionalProperties": g.of(t.Elem())}
	case reflect.Struct:
		return map[string]any{"$ref": "#/components/schemas/" + g.component(t)}
	}
	panic(fmt.Sprintf("api: no schema for %s", t))
}

// component adds the schema of a struct and returns its name: the type
// name, prefixed by its package name outside this package.
func (g *schemas) component(t reflect.Type) string {
	if n, ok := g.names[t]; ok {
		return n
	}
	name := t.Name()
	if pkg := t.PkgPath(); pkg != reflect.TypeOf(Server{}).PkgPath() {
		base := pkg[strings.LastIndex(pkg, "/")+1:]
		name = strings.ToUpper(base[:1]) + base[1:] + name
	}
	g.names[t] = name
	props := map[string]any{}
	var required []string
	for i := range t.NumField() {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || tag == "-" {
			continue
		}
		if tag == "" {
			tag = f.Name
		}
		s := g.of(f.Type)
		if e := f.Tag.Get("enum"); e != "" {
			s["enum"] = strings.Split(e, ",")
		}
		props[tag] = s
		if !strings.Contains(f.Tag.Get("json"), ",omitempty") {
			required = append(required, tag)
		}
	}
	sort.Strings(required)
	sch := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		sch["required"] = required
	}
	g.components[name] = sch
	return name
}

// nullable allows null besides the schema s.
func nullable(s map[string]any) map[string]any {
	if t, ok := s["type"].(string); ok {
		s["type"] = []string{t, "null"}
		return s
	}
	return map[string]any{"anyOf": []any{s, map[string]any{"type": "null"}}}
}

var document = sync.OnceValues(Document)

func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	b, err := document()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}
