package main

import (
	"bytes"
	"testing"
)

func TestFollowRejectsUnsafeScopesBeforeConnecting(t *testing.T) {
	for _, extra := range [][]string{{"--from", "0"}, {"--from", "18446744073709551615"}, {"--rate", "NaN"}, {"--poll", "1ms"}, {"--node", "duplicate", "--node", "duplicate", "--rpc", "http://127.0.0.1:2"}} {
		args := []string{"--db", "synthetic", "--name", "synthetic-follow", "--config", "does-not-exist", "--from", "1", "--rpc", "http://127.0.0.1:1"}
		args = append(args, extra...)
		var out, err bytes.Buffer
		if code := runFollow(args, &out, &err); code != exitUsage {
			t.Fatal(extra, code, err.String())
		}
	}
}
