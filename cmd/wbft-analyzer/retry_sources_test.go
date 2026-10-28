package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRetrySourceUsageAndInputErrorsDoNotExposePaths(t *testing.T) {
	for _, args := range [][]string{{"retry-sources"}, {"retry-sources", "--unknown=secret-host"}, {"retry-sources", "--journal", "/private/operator-source", "--source-limits", "/missing/private-limit"}} {
		var out, err bytes.Buffer
		code := run(args, &out, &err)
		if code == exitOK || strings.Contains(out.String()+err.String(), "operator-source") || strings.Contains(err.String(), "private-limit") || strings.Contains(err.String(), "secret-host") {
			t.Fatal(code, out.String(), err.String())
		}
	}
}
