package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutionWitnessUsageAndSourceRefusalDoNotExposePathsOrCredentials(t *testing.T) {
	t.Setenv("WBFT_ANALYZER_DB", "postgres://synthetic-sensitive-input")
	var out, errout bytes.Buffer
	if code := runIngest([]string{"execution-witness", "-h"}, &out, &errout); code != 0 || !strings.Contains(errout.String(), "headers-dataset-id") {
		t.Fatal(code, errout.String())
	}
	if strings.Contains(errout.String(), "synthetic-sensitive-input") {
		t.Fatal("help exposed an environment credential")
	}
	for _, args := range [][]string{{"--unknown=synthetic-sensitive-input"}, {"--db=postgres://synthetic-sensitive-input", "--dataset-id=-1"}} {
		out.Reset()
		errout.Reset()
		if code := runExecutionWitness(args, &out, &errout); code != exitUsage || strings.Contains(errout.String(), "synthetic-sensitive-input") || out.Len() != 0 {
			t.Fatal(code, out.String(), errout.String())
		}
	}
	dir := t.TempDir()
	name := filepath.Join(dir, "synthetic-sensitive-input.json")
	if err := os.WriteFile(name, []byte(`{"format":"unsupported"}`), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errout.Reset()
	code := runExecutionWitness([]string{"--db=postgres://synthetic-sensitive-input", "--dataset-id=1", "--headers-dataset-id=2", "--manifest=" + name, "--root=" + dir, "--helper=" + name, "--helper-sha256=" + strings.Repeat("0", 64)}, &out, &errout)
	if code != exitDataErr || out.Len() != 0 || strings.Contains(errout.String(), "synthetic-sensitive-input") {
		t.Fatal(code, out.String(), errout.String())
	}
}
