package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRun: the usage, the version, an unknown command, a command that is
// not built yet and the serve checks made before the database is opened
// give their exit codes and messages.
func TestRun(t *testing.T) {
	t.Setenv("WBFT_ANALYZER_TOKEN", "short")
	for _, c := range []struct {
		args []string
		code int
		out  string // in stdout or stderr
	}{
		{nil, exitUsage, "Commands:"},
		{[]string{"help"}, exitOK, "Commands:"},
		{[]string{"version"}, exitOK, "wbft-analyzer dev"},
		{[]string{"nope"}, exitUsage, `unknown command "nope"`},
		{[]string{"follow"}, exitUsage, "Usage of follow"},
		{[]string{"serve", "--db", "x", "--listen", "0.0.0.0:8080"}, exitUsage, "needs --auth token"},
		{[]string{"serve", "--db", "x", "--listen", ":8080"}, exitUsage, "needs --auth token"},
		{[]string{"serve", "--db", "x", "--auth", "token"}, exitUsage, "of 32 characters or more"},
		{[]string{"serve", "--db", "x", "--auth", "oidc"}, exitUnavailable, "--auth oidc is not available yet"},
		{[]string{"ingest", "reports", "r.json"}, exitUsage, "Usage: wbft-analyzer ingest reports"},
		{[]string{"ingest", "range"}, exitUsage, "Usage of ingest range"},
	} {
		var stdout, stderr bytes.Buffer
		code := run(c.args, &stdout, &stderr)
		if code != c.code || !strings.Contains(stdout.String()+stderr.String(), c.out) {
			t.Errorf("%v: code %d, output %q%q; want %d and %q", c.args, code, stdout.String(), stderr.String(), c.code, c.out)
		}
	}
}
