package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080": true, "127.0.0.2:80": true, "[::1]:8080": true, "localhost:8080": true,
		":8080": false, "0.0.0.0:8080": false, "[::]:8080": false, "10.0.0.1:8080": false, "example.com:80": false, "127.0.0.1": false,
	} {
		if got := Loopback(addr); got != want {
			t.Errorf("Loopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

// TestGuard: the checks made before any handler, so no store is needed;
// a request that passes them reaches the API's 404 for an unknown path.
func TestGuard(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	open := (&Server{}).Handler()
	authed := (&Server{Token: token}).Handler()
	for _, c := range []struct {
		name    string
		h       http.Handler
		method  string
		host    string
		headers map[string]string
		code    int
		static  bool
	}{
		{"loopback host", open, "GET", "127.0.0.1:8080", nil, 404, false},
		{"localhost", open, "GET", "localhost:8080", nil, 404, false},
		{"ipv6 loopback", open, "GET", "[::1]:8080", nil, 404, false},
		{"rebound name", open, "GET", "attacker.example:8080", nil, 421, false},
		{"no token", authed, "GET", "analyzer.example", nil, 401, false},
		{"wrong token", authed, "GET", "analyzer.example", map[string]string{"Authorization": "Bearer " + strings.Repeat("x", 32)}, 401, false},
		{"not bearer", authed, "GET", "analyzer.example", map[string]string{"Authorization": "Basic " + token}, 401, false},
		{"token", authed, "GET", "analyzer.example", map[string]string{"Authorization": "Bearer " + token}, 404, false},
		{"form post", open, "POST", "127.0.0.1:8080", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, 415, false},
		{"no content type", open, "PUT", "127.0.0.1:8080", nil, 415, false},
		{"cross-origin post", open, "POST", "127.0.0.1:8080",
			map[string]string{"Content-Type": "application/json", "Origin": "http://attacker.example"}, 403, false},
		{"same-origin post", open, "POST", "127.0.0.1:8080",
			map[string]string{"Content-Type": "application/json; charset=utf-8", "Origin": "http://127.0.0.1:8080"}, 404, false},
		{"post without origin", open, "POST", "127.0.0.1:8080", map[string]string{"Content-Type": "application/json"}, 404, false},
		// The front end's files: no token needed, loopback host without
		// one, read only.
		{"page", open, "GET", "127.0.0.1:8080", nil, 404, true},
		{"page, rebound name", open, "GET", "attacker.example:8080", nil, 421, true},
		{"page without token", authed, "GET", "analyzer.example", nil, 404, true},
		{"page post", authed, "POST", "analyzer.example", map[string]string{"Content-Type": "application/json"}, 405, true},
	} {
		path := "/v1/nope"
		if c.static {
			path = "/index.html"
		}
		req := httptest.NewRequest(c.method, path, strings.NewReader("{}"))
		req.Host = c.host
		for k, v := range c.headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		c.h.ServeHTTP(rec, req)
		if rec.Code != c.code {
			t.Errorf("%s: %d %s, want %d", c.name, rec.Code, rec.Body, c.code)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: security headers missing: %v", c.name, rec.Header())
		}
		if csp := rec.Header().Get("Content-Security-Policy"); (c.static && csp != webCSP) || (!c.static && csp != apiCSP) {
			t.Errorf("%s: CSP %q", c.name, csp)
		}
		if rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: content type %q", c.name, rec.Header().Get("Content-Type"))
		}
	}
}
