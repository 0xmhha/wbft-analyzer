package web

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func get(t *testing.T, files fstest.MapFS, path string) (int, string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	handler(files).ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String()
}

// TestHandler: the page, hashed assets cached for good, no directory
// listing, and 503 when the front end is not built.
func TestHandler(t *testing.T) {
	built := fstest.MapFS{
		"dist/README.md":              {Data: []byte("placeholder")},
		"dist/app/index.html":         {Data: []byte("<!doctype html><title>wbft-analyzer</title>")},
		"dist/app/assets/index-1a.js": {Data: []byte("console.log(1)")},
	}
	for _, c := range []struct {
		path, cache, body string
		code              int
	}{
		{"/", "no-cache", "<title>wbft-analyzer</title>", 200},
		{"/assets/index-1a.js", "public, max-age=31536000, immutable", "console.log(1)", 200},
		{"/assets/", "", "404", 404},
		{"/missing.js", "", "404", 404}, // net/http drops Cache-Control on errors
	} {
		code, cache, body := get(t, built, c.path)
		if code != c.code || cache != c.cache || !strings.Contains(body, c.body) {
			t.Errorf("%s: %d %q %q, want %d %q %q", c.path, code, cache, body, c.code, c.cache, c.body)
		}
	}
	code, _, body := get(t, fstest.MapFS{"dist/README.md": {Data: []byte("placeholder")}}, "/")
	if code != 503 || !strings.Contains(body, "npm run build") {
		t.Errorf("not built: %d %q", code, body)
	}
}

// TestBuilt: in CI the front end is built before the tests
// (WBFT_ANALYZER_WEB_BUILT=1), and the binary then embeds it.
func TestBuilt(t *testing.T) {
	if os.Getenv("WBFT_ANALYZER_WEB_BUILT") == "" {
		t.Skip("WBFT_ANALYZER_WEB_BUILT is not set")
	}
	if !Built() {
		t.Fatal("the front end is not embedded")
	}
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `<script type="module"`) {
		t.Fatalf("embedded page: %d %q", rec.Code, rec.Body)
	}
}
