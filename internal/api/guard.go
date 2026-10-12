package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// MinTokenLen is the shortest bearer token the server accepts.
const MinTokenLen = 32

// ErrShortToken is a bearer token shorter than MinTokenLen.
var ErrShortToken = errors.New("api: the token is shorter than 32 characters")

// Loopback reports whether a listen address (host:port) accepts only
// connections from this machine. An empty host listens on every interface.
func Loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return loopbackHost(host)
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// guard wraps the API with the checks every request goes through:
// security headers, then the bearer token when the server has one, or,
// without a token, a loopback Host (so that a web page cannot reach the
// local server under a name of its own, DNS rebinding), and for writes a
// JSON body from the same origin (so that a page cannot post a form to
// it).
func (s *Server) guard(next http.Handler) http.Handler {
	var want [32]byte
	if s.Token != "" {
		want = sha256.Sum256([]byte(s.Token))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if s.Token != "" {
			got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			// Compare digests: equal length, constant time.
			sum := sha256.Sum256([]byte(got))
			if !ok || subtle.ConstantTimeCompare(sum[:], want[:]) != 1 {
				h.Set("WWW-Authenticate", `Bearer realm="wbft-analyzer"`)
				writeError(w, http.StatusUnauthorized, "a bearer token is required")
				return
			}
		} else if host := hostOnly(r.Host); !loopbackHost(host) {
			writeError(w, http.StatusMisdirectedRequest, "the server answers only to a loopback host name")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && !sameOrigin(o, r.Host) {
				writeError(w, http.StatusForbidden, "cross-origin writes are refused")
				return
			}
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, "the body must be application/json")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, s.maxBody())
		}
		next.ServeHTTP(w, r)
	})
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && strings.EqualFold(u.Host, host)
}
