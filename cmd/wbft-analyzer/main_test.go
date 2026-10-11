package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRun: the usage, the version, an unknown command and a command that
// is not built yet give their exit codes and messages.
func TestRun(t *testing.T) {
	for _, c := range []struct {
		args []string
		code int
		out  string // in stdout or stderr
	}{
		{nil, exitUsage, "Commands:"},
		{[]string{"help"}, exitOK, "Commands:"},
		{[]string{"version"}, exitOK, "wbft-analyzer dev"},
		{[]string{"nope"}, exitUsage, `unknown command "nope"`},
		{[]string{"serve", "--db", "x"}, exitUnavailable, "serve: not available yet"},
		{[]string{"ingest", "reports", "r.json"}, exitUsage, "Usage: wbft-analyzer ingest reports"},
		{[]string{"ingest", "range"}, exitUsage, "not available yet"},
	} {
		var stdout, stderr bytes.Buffer
		code := run(c.args, &stdout, &stderr)
		if code != c.code || !strings.Contains(stdout.String()+stderr.String(), c.out) {
			t.Errorf("%v: code %d, output %q%q; want %d and %q", c.args, code, stdout.String(), stderr.String(), c.code, c.out)
		}
	}
}
