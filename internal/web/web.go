// Package web serves the front end (web/, a static React/d3 page) from the
// files embedded at build time: `npm run build` in web/ writes them to
// dist/app before `go build`. A binary built without them serves the API
// only; its pages answer 503 and say how to build them.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Built reports whether the front end is embedded.
func Built() bool {
	_, err := fs.Stat(dist, "dist/app/index.html")
	return err == nil
}

// Handler serves the embedded front end. Files under /assets/ are named by
// their content hash and are cached for good; the page itself is not
// cached, so that a new build is picked up.
func Handler() http.Handler {
	return handler(dist)
}

func handler(files fs.FS) http.Handler {
	app, err := fs.Sub(files, "dist/app")
	if _, statErr := fs.Stat(files, "dist/app/index.html"); err != nil || statErr != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("The front end is not built into this binary: run `npm ci && npm run build` in web/, then build again.\n"))
		})
	}
	serve := http.FileServerFS(app)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No directory listings: the only directory served is the root,
		// as its index.html.
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		serve.ServeHTTP(w, r)
	})
}
