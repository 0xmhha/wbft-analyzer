package main

import (
	"bytes"
	"encoding/json"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/p2p/transport"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReceiveFailureSourceUsageAndInputErrorsDoNotExposePaths(t *testing.T) {
	for _, args := range [][]string{{"receive-failures"}, {"receive-failures", "--unknown=secret-host"}, {"receive-failures", "--journal", "/private/operator-source", "--source-limits", "/missing/private-limit"}} {
		var out, err bytes.Buffer
		code := run(args, &out, &err)
		if code == exitOK || strings.Contains(out.String()+err.String(), "operator-source") || strings.Contains(err.String(), "private-limit") || strings.Contains(err.String(), "secret-host") {
			t.Fatal(code, out.String(), err.String())
		}
	}
}

func TestReceiveFailureSourceCLIOriginalPartialAndContradiction(t *testing.T) {
	directory := t.TempDir()
	limitFile := filepath.Join(t.TempDir(), "limits.json")
	limits := journal.ReceiveFailureLimits{Caches: 8, Inbox: journal.InboxLimits{Core: journal.CoreSourceLimits{Records: 1000, Runs: 8, Steps: 100, Environments: 100, Outputs: 1000, Bytes: 1 << 20}, Operations: 1000, Entries: 100, Peers: 10, Frames: 100, Bytes: 1 << 20}}
	raw, err := json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(limitFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// Only new local writer metadata is created, without source or packet edits.
	for i, entries := range []uint64{2, 3} {
		w, err := journal.Open(journal.Options{Dir: directory, Synchronous: true}, journal.Identity{Run: "source-cli-metadata", ChainID: big.NewInt(7), Core: journal.CoreOptions{CachePolicy: &journal.CachePolicyOptions{Profile: journal.AcceptedCompletedCacheProfile, Limits: transport.CachePolicyLimits{ReceivePending: 8, ReceivePerPeer: 4, WritePending: 8, WritePerPeer: 4}}, ReceiveFailureCache: &journal.ReceiveFailureCacheOptions{Profile: journal.ReceiveFailureCacheProfile, Entries: entries}}})
		if err != nil {
			t.Fatal(err)
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		records, err := journal.ReadAll(nil, directory)
		if err != nil {
			t.Fatal(err)
		}
		expected, _ := journal.CheckReceiveFailureSources(records, limits)
		var stdout, stderr bytes.Buffer
		code := run([]string{"receive-failures", "--journal", directory, "--source-limits", limitFile}, &stdout, &stderr)
		expectedCode := exitUnavailable
		if i == 1 {
			expectedCode = exitDataErr
		}
		var actual journal.ReceiveFailureCheck
		if err = json.Unmarshal(stdout.Bytes(), &actual); err != nil || code != expectedCode || stderr.Len() != 0 || !reflect.DeepEqual(actual, expected) {
			t.Fatal(code, expectedCode, actual, expected, err, stderr.String())
		}
	}
}
