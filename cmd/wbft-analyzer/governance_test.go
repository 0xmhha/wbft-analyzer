package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/jackc/pgx/v5"
)

func TestGovernanceArgumentAndErrorPrivacy(t *testing.T) {
	const marker = "synthetic-secret-marker"
	t.Setenv("WBFT_ANALYZER_DB", "postgres://"+marker+"@invalid/db")
	for _, args := range [][]string{
		{"-h"},
		{"--unknown=" + marker},
		{"--rate=" + marker},
		{"--name", "a", "--archive", "/missing/" + marker},
		{"--name", "a", "--rpc", "https://" + marker + "@invalid", "--from", "0x0", "--to", "0x400"},
		{"--name", "a", "--rpc", "https://" + marker + "@invalid", "--from", "0x0", "--to", "0x1", "--proposal", marker},
	} {
		var out, err bytes.Buffer
		code := runGovernance(args, &out, &err)
		if args[0] != "-h" && code == exitOK {
			t.Fatal("invalid arguments accepted")
		}
		if strings.Contains(out.String()+err.String(), marker) {
			t.Fatal("sensitive argument printed")
		}
	}
}

func TestGovernanceCLIArchiveRPCAndIdempotence(t *testing.T) {
	dsn := os.Getenv("WBFT_ANALYZER_TEST_DSN")
	if dsn == "" {
		t.Skip("WBFT_ANALYZER_TEST_DSN is not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var random [6]byte
	if _, err = rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	schema := "governance_" + hex.EncodeToString(random[:])
	if _, err = conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") }()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	const path = "../../internal/source/governance/testdata/capture.json"
	a, _, err := governance.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(args []string) ingest.GovernanceResult {
		t.Helper()
		var out, stderr bytes.Buffer
		code := runIngest(append([]string{"governance", "--db", u.String()}, args...), &out, &stderr)
		if code != exitOK || stderr.Len() != 0 {
			t.Fatal(code, stderr.String())
		}
		var result ingest.GovernanceResult
		if err = json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	r := invoke([]string{"--name", "archive-gov", "--archive", path})
	again := invoke([]string{"--name", "archive-gov", "--archive", path})
	if r.Skipped || r.Calls != 9 || !again.Skipped || again.DatasetID != r.DatasetID {
		t.Fatal(r, again)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requests []struct {
			Method string   `json:"method"`
			Params []string `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&requests) != nil || len(requests) != 1 {
			http.Error(w, "invalid", 400)
			return
		}
		i := int(calls.Add(1)) - 1
		if i >= len(a.Replies) || a.Replies[i].Method != requests[0].Method || !slices.Equal(a.Replies[i].Params, requests[0].Params) {
			http.Error(w, "unexpected", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var response map[string]json.RawMessage
		if json.Unmarshal(a.Replies[i].Response, &response) != nil {
			http.Error(w, "fixture", 500)
			return
		}
		response["id"] = json.RawMessage("1")
		_ = json.NewEncoder(w).Encode([]map[string]json.RawMessage{response})
	}))
	defer server.Close()
	live := invoke([]string{"--name", "rpc-gov", "--rpc", server.URL, "--from", a.From, "--to", a.To, "--instance", a.Instances[0], "--proposal", a.Proposals[0].Instance + ":" + a.Proposals[0].ID, "--rate", "5"})
	if live.Skipped || live.Calls != 9 || calls.Load() != 9 || live.NetworkID != r.NetworkID || live.DatasetID == r.DatasetID {
		t.Fatal(live, calls.Load())
	}
}
