package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestScenarioUsageRefusesUnsupportedOrUnboundedScopes(t *testing.T) {
	t.Setenv("WBFT_ANALYZER_DB", "postgres://private-password@invalid/scenario")
	for _, args := range [][]string{nil, {"run"}, {"fit"}, {"fit", "--from", "1", "--to", "10001"}, {"fit", "--clock", "invented"}, {"fit", "--wire-metric", "corrected"}, {"fit", "--seeds", "129"}, {"fit", "--skew-ms", "-1"}} {
		var out, err bytes.Buffer
		if code := runScenario(args, &out, &err); code != exitUsage {
			t.Fatalf("scope %v returned %d", args, code)
		}
		if strings.Contains(err.String(), "private-password") {
			t.Fatal("DSN leaked through flag defaults")
		}
	}
}

func TestScenarioRejectsUnknownModelBeforeOpeningStorage(t *testing.T) {
	var out, err bytes.Buffer
	args := []string{"fit", "--db", "postgres://invalid/example", "--dataset", "1", "--chain", "synthetic.rlp", "--origin", "2026-01-01T00:00:00Z", "--from", "1", "--to", "2", "--model", "invented"}
	if code := runScenario(args, &out, &err); code != exitUsage {
		t.Fatal(code, err.String())
	}
}
