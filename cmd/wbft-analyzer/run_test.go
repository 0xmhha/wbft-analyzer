package main

import (
	"bytes"
	"testing"
)

func TestRunUsageAndChainIdentity(t *testing.T) {
	for _, args := range [][]string{{"ingest", "run"}, {"ingest", "run", "--db", "x", "--manifest", "m", "--chainbench", "w"}, {"ingest", "run", "--db", "x", "--chainbench", "w", "--name", "n"}} {
		var out, errout bytes.Buffer
		if code := run(args, &out, &errout); code != exitUsage {
			t.Fatal(args, code, errout.String())
		}
	}
	n, err := chainID("0x205b")
	if err != nil || n.String() != "8283" {
		t.Fatal(n, err)
	}
	for _, raw := range []string{"8283", "0x-1", "0xxyz"} {
		if _, err = chainID(raw); err == nil {
			t.Fatal("invalid chain ID", raw)
		}
	}
}
