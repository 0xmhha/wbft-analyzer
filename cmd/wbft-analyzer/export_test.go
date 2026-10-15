package main

import (
	"bytes"
	"testing"
)

func TestExportArguments(t *testing.T) {
	t.Setenv("WBFT_ANALYZER_DB", "")
	for _, args := range [][]string{nil, {"--db", "x"}, {"--db", "x", "--dataset", "chosen", "--out", "new", "--target", "unclassified"}, {"--db", "x", "--dataset", "chosen", "--out", "new", "extra"}} {
		var out, errout bytes.Buffer
		if code := runExport(args, &out, &errout); code != exitUsage {
			t.Fatalf("arguments accepted: %v, %d", args, code)
		}
	}
	var out, errout bytes.Buffer
	if code := runExport([]string{"-h"}, &out, &errout); code != exitOK {
		t.Fatalf("help: %d %s", code, errout.String())
	}
}
