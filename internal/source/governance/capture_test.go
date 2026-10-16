package governance

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	client "github.com/0xmhha/wbft-analyzer/internal/source/rpc"
)

var testAddr = "0x" + strings.Repeat("1", 40)
var testHash = "0x" + strings.Repeat("2", 64)

func raw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func envelope(v any) json.RawMessage {
	return raw(map[string]any{"jsonrpc": "2.0", "id": 1, "result": v})
}
func fixture() Archive {
	from, to := "0x20000000000001", "0x20000000000002"
	op := map[string]any{"number": from, "tx": 0, "txHash": testHash, "path": nil, "from": testAddr, "instance": testAddr,
		"input": "0x" + hex.EncodeToString([]byte("private-opaque-data")), "effective": false, "view": false, "result": "private-result-label",
		"logs": []any{map[string]any{"address": testAddr, "topics": []string{testHash}, "data": "0x" + hex.EncodeToString([]byte("private-log-data"))}}, "verified": false, "executingProposalId": nil, "validatorChange": nil, "private-extra": "discard-me"}
	p := map[string]any{"id": from, "actionType": testHash, "proposer": testAddr, "status": 4, "approved": 3, "rejected": 1, "requiredApprovals": 3, "executionCount": "0x0", "callData": "0x" + hex.EncodeToString([]byte("private-proposal-data"))}
	info := map[string]any{"impl": "wbft", "address": testAddr, "chainId": json.Number("9007199254740993"), "genesisHash": testHash, "head": map[string]any{"number": "9007199254741000", "hash": testHash}, "private-extra": "discard-me"}
	m := map[string]any{"number": to, "hash": testHash, "healthy": false, "authority": "module", "modes": map[string]string{testAddr: "projection-only"}, "validators": []string{testAddr}, "blsPublicKeys": []string{"0x" + strings.Repeat("3", 96)}, "gasTip": from, "blacklisted": []string{}, "authorized": []string{}}
	s := map[string]any{"number": to, "instance": testAddr, "mode": "projection-only", "memberVersion": from, "members": []string{testAddr}, "quorum": "0x1", "proposalExpiry": "0x100", "currentProposalId": from, "maxActiveProposalsPerMember": "0x10", "proposals": []any{p}, "inexact": true}
	older := map[string]any{}
	for k, v := range op {
		older[k] = v
	}
	older["number"] = "0x1"
	a := Archive{Format: Format, EnvelopeOrigin: "supplied", From: from, To: to, Instances: []string{testAddr}, Proposals: []ProposalKey{{Instance: testAddr, ID: from}}}
	plan, err := Requests(from, to, a.Instances, a.Proposals)
	if err != nil {
		panic(err)
	}
	for _, q := range plan {
		var value any
		switch q.Method {
		case "wbft_nodeInfo":
			value = info
		case "wbft_mirror":
			value = m
		case "wbft_govOps":
			value = []any{op}
		case "wbft_mirrorFaults":
			value = []any{map[string]any{"number": to, "kind": "gap", "instance": testAddr, "what": "private-fault-description", "gapFrom": "0x0", "gapTo": from}}
		case "wbft_validatorChanges":
			value = []any{map[string]any{"number": to, "ops": []any{}, "epoch": map[string]any{"Candidates": []string{testAddr}, "Validators": []string{testAddr}, "Added": nil, "Removed": nil}}}
		case "wbft_mirrorState":
			value = s
		case "wbft_govProposal":
			value = map[string]any{"instance": testAddr, "id": from, "proposal": p, "ops": []any{older}}
		}
		a.Replies = append(a.Replies, Reply{Method: q.Method, Params: q.Params, Response: envelope(value)})
	}
	return a
}

func resultMap(t *testing.T, a *Archive, i int) map[string]any {
	t.Helper()
	var env map[string]json.RawMessage
	if json.Unmarshal(a.Replies[i].Response, &env) != nil {
		t.Fatal("envelope")
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(env["result"]))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		t.Fatal("result")
	}
	return value
}
func replaceResult(a *Archive, i int, v any) { a.Replies[i].Response = envelope(v) }
func alterOperation(t *testing.T, a *Archive, change func(map[string]any)) {
	t.Helper()
	var env map[string]json.RawMessage
	_ = json.Unmarshal(a.Replies[2].Response, &env)
	var rows []map[string]any
	if json.Unmarshal(env["result"], &rows) != nil {
		t.Fatal("operations")
	}
	change(rows[0])
	replaceResult(a, 2, rows)
}

func TestExactScopesAuthorityAndOpaqueValues(t *testing.T) {
	a := fixture()
	s, err := Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	if s.Atomic || s.Before.ChainID != "9007199254740993" || s.Before.Address != testAddr || len(s.Calls) != 9 {
		t.Fatal(s)
	}
	var m Mirror
	_ = json.Unmarshal(s.Calls[1].Data, &m)
	if m.Authority != "module" || m.Healthy || m.GasTip == nil || *m.GasTip != a.From {
		t.Fatal(m)
	}
	var ops []Operation
	_ = json.Unmarshal(s.Calls[2].Data, &ops)
	if len(ops) != 1 || ops[0].Number != a.From || ops[0].Effective || ops[0].Verified || ops[0].Result != "unknown" || ops[0].ValidatorChange.Status != "not-reported" || ops[0].ExecutingProposalID != nil {
		t.Fatal(ops)
	}
	if ops[0].Input.SHA256 != digest([]byte("private-opaque-data")) || ops[0].Logs[0].Data.Length != len("private-log-data") {
		t.Fatal(ops)
	}
	var fs []Fault
	_ = json.Unmarshal(s.Calls[3].Data, &fs)
	if len(fs) != 1 || !fs[0].BoundsKnown || *fs[0].GapFrom != "0x0" || *fs[0].GapTo != a.From {
		t.Fatal(fs)
	}
	var st State
	_ = json.Unmarshal(s.Calls[5].Data, &st)
	if !st.Inexact || st.MemberVersion != a.From || st.Proposals[0].ID != a.From {
		t.Fatal(st)
	}
	var h ProposalHistory
	_ = json.Unmarshal(s.Calls[6].Data, &h)
	if h.Ops[0].Number != "0x1" || s.Calls[6].Request.Scope != "proposal-full-history-current-state" || s.Calls[5].Request.Scope != "historical-state" {
		t.Fatal(h)
	}
	b := string(raw(s))
	for _, secret := range []string{"private-", "discard-me", hex.EncodeToString([]byte("private-opaque-data")), hex.EncodeToString([]byte("private-log-data")), hex.EncodeToString([]byte("private-proposal-data"))} {
		if strings.Contains(b, secret) {
			t.Fatalf("opaque value retained: %s", secret)
		}
	}
	if s.Calls[2].SHA256 != digest(a.Replies[2].Response) {
		t.Fatal("wrong envelope hash")
	}
}

func TestUnavailableEmptyLegacyGapAndNullAnnotationsStayDistinct(t *testing.T) {
	for _, value := range []json.RawMessage{json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":null}`), json.RawMessage(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"private-error","data":"discard-me"}}`)} {
		a := fixture()
		a.Replies[2].Response = value
		s, err := Normalize(a)
		if err != nil || s.Calls[2].Status != "unavailable" || string(s.Calls[2].Data) != "null" || strings.Contains(string(raw(s)), "private-error") {
			t.Fatal(s, err)
		}
	}
	a := fixture()
	replaceResult(&a, 2, []any{})
	replaceResult(&a, 3, []any{map[string]any{"number": a.To, "kind": "gap", "instance": testAddr, "what": "no history of blocks 0..2: private-fault-description"}})
	s, err := Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	if s.Calls[2].Status != "available" || string(s.Calls[2].Data) != "[]" {
		t.Fatal(s.Calls[2])
	}
	var fs []Fault
	_ = json.Unmarshal(s.Calls[3].Data, &fs)
	if fs[0].BoundsKnown || fs[0].GapFrom != nil || fs[0].GapTo != nil {
		t.Fatal("description was interpreted as a range", fs)
	}
	a = fixture()
	alterOperation(t, &a, func(op map[string]any) {
		op["executingProposalId"] = a.From
		op["validatorChange"] = map[string]any{"private": "discard-me"}
	})
	s, err = Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	var ops []Operation
	_ = json.Unmarshal(s.Calls[2].Data, &ops)
	if ops[0].ExecutingProposalID == nil || *ops[0].ExecutingProposalID != a.From || ops[0].ValidatorChange.Status != "unsupported" || ops[0].ValidatorChange.Value == nil {
		t.Fatal(ops)
	}
}

func TestMalformedOrForeignCapturesAreRejected(t *testing.T) {
	cases := map[string]func(*Archive){
		"missing call":      func(a *Archive) { a.Replies = a.Replies[:len(a.Replies)-1] },
		"duplicate call":    func(a *Archive) { a.Replies[3] = a.Replies[2] },
		"management method": func(a *Archive) { a.Replies[1].Method = "admin_mirrorRebuild" },
		"foreign range":     func(a *Archive) { a.Replies[2].Params = []string{"0x1", a.To} },
		"foreign node": func(a *Archive) {
			v := resultMap(t, a, len(a.Replies)-1)
			v["address"] = "0x" + strings.Repeat("3", 40)
			replaceResult(a, len(a.Replies)-1, v)
		},
		"foreign chain": func(a *Archive) {
			v := resultMap(t, a, len(a.Replies)-1)
			v["chainId"] = 9
			replaceResult(a, len(a.Replies)-1, v)
		},
		"foreign genesis": func(a *Archive) {
			v := resultMap(t, a, len(a.Replies)-1)
			v["genesisHash"] = "0x" + strings.Repeat("3", 64)
			replaceResult(a, len(a.Replies)-1, v)
		},
		"unavailable identity": func(a *Archive) { a.Replies[0].Response = envelope(nil) },
		"duplicate envelope key": func(a *Archive) {
			a.Replies[2].Response = json.RawMessage(`{"jsonrpc":"2.0","id":1,"id":2,"result":[]}`)
		},
		"ambiguous envelope": func(a *Archive) {
			a.Replies[2].Response = json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":[],"error":{"code":-1}}`)
		},
		"null error":            func(a *Archive) { a.Replies[2].Response = json.RawMessage(`{"jsonrpc":"2.0","id":1,"error":null}`) },
		"foreign state":         func(a *Archive) { v := resultMap(t, a, 5); v["number"] = "0x1"; replaceResult(a, 5, v) },
		"foreign proposal":      func(a *Archive) { v := resultMap(t, a, 6); v["id"] = "0x1"; replaceResult(a, 6, v) },
		"wrong operation range": func(a *Archive) { alterOperation(t, a, func(op map[string]any) { op["number"] = "0x1" }) },
		"missing boolean":       func(a *Archive) { alterOperation(t, a, func(op map[string]any) { delete(op, "verified") }) },
		"null boolean":          func(a *Archive) { alterOperation(t, a, func(op map[string]any) { op["effective"] = nil }) },
		"negative path":         func(a *Archive) { alterOperation(t, a, func(op map[string]any) { op["path"] = []int{-1} }) },
		"fractional tx":         func(a *Archive) { alterOperation(t, a, func(op map[string]any) { op["tx"] = 0.5 }) },
		"overflow tx": func(a *Archive) {
			alterOperation(t, a, func(op map[string]any) { op["tx"] = json.Number("4294967296") })
		},
		"missing annotation": func(a *Archive) { alterOperation(t, a, func(op map[string]any) { delete(op, "validatorChange") }) },
		"malformed calldata": func(a *Archive) { alterOperation(t, a, func(op map[string]any) { op["input"] = "0x0" }) },
		"duplicate operation coordinate": func(a *Archive) {
			var env map[string]json.RawMessage
			_ = json.Unmarshal(a.Replies[2].Response, &env)
			var rows []json.RawMessage
			_ = json.Unmarshal(env["result"], &rows)
			replaceResult(a, 2, append(rows, rows[0]))
		},
		"one-sided gap": func(a *Archive) {
			replaceResult(a, 3, []any{map[string]any{"number": a.To, "kind": "gap", "instance": testAddr, "what": "synthetic", "gapFrom": "0x0"}})
		},
		"reversed gap": func(a *Archive) {
			replaceResult(a, 3, []any{map[string]any{"number": a.To, "kind": "gap", "instance": testAddr, "what": "synthetic", "gapFrom": "0x2", "gapTo": "0x1"}})
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			a := fixture()
			change(&a)
			if _, err := Normalize(a); err == nil {
				t.Fatal("invalid capture accepted")
			}
		})
	}
}

func TestCanonicalUint64RangesAndRequestBounds(t *testing.T) {
	for _, pair := range [][2]string{{"0x0", "0x3ff"}, {"0xffffffffffffffff", "0xffffffffffffffff"}, {"0x20000000000001", "0x20000000000002"}} {
		if _, _, err := Range(pair[0], pair[1]); err != nil {
			t.Fatal(pair, err)
		}
	}
	for _, pair := range [][2]string{{"0x0", "0x400"}, {"0x1", "0x0"}, {"0x00", "0x1"}, {"0xA", "0xb"}, {"1", "1"}, {"0x10000000000000000", "0x10000000000000000"}} {
		if _, _, err := Range(pair[0], pair[1]); err == nil {
			t.Fatal(pair)
		}
	}
	for _, instances := range [][]string{{testAddr, testAddr}, {"secret"}, make([]string, 33)} {
		if _, err := Requests("0x0", "0x1", instances, nil); err == nil {
			t.Fatal(instances)
		}
	}
	if _, err := Requests("0x0", "0x1", nil, []ProposalKey{{Instance: testAddr, ID: "0x1"}, {Instance: testAddr, ID: "0x1"}}); err == nil {
		t.Fatal("duplicate proposal accepted")
	}
}

func TestCaseAliasesAndAbsentStateFieldsCannotMasqueradeAsReportedValues(t *testing.T) {
	for name, change := range map[string]func(*Archive){
		"mirror alias":           func(a *Archive) { v := resultMap(t, a, 1); v["GasTip"] = "0x1"; replaceResult(a, 1, v) },
		"missing mirror gas tip": func(a *Archive) { v := resultMap(t, a, 1); delete(v, "gasTip"); replaceResult(a, 1, v) },
		"foreign implementation": func(a *Archive) { v := resultMap(t, a, 0); v["impl"] = "other"; replaceResult(a, 0, v) },
		"nested identity alias": func(a *Archive) {
			v := resultMap(t, a, 0)
			h := v["head"].(map[string]any)
			h["Hash"] = testHash
			replaceResult(a, 0, v)
		},
		"null inexact": func(a *Archive) { v := resultMap(t, a, 5); v["inexact"] = nil; replaceResult(a, 5, v) },
	} {
		t.Run(name, func(t *testing.T) {
			a := fixture()
			change(&a)
			if _, err := Normalize(a); err == nil {
				t.Fatal("ambiguous metadata accepted")
			}
		})
	}
	a := fixture()
	v := resultMap(t, &a, 5)
	v["validators"] = []string{}
	replaceResult(&a, 5, v)
	s, err := Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	var st State
	_ = json.Unmarshal(s.Calls[5].Data, &st)
	found := false
	for _, name := range st.ReportedFields {
		found = found || name == "validators"
	}
	if !found {
		t.Fatal(st)
	}
	a = fixture()
	s, err = Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(s.Calls[5].Data, &st)
	for _, name := range st.ReportedFields {
		if name == "validators" {
			t.Fatal("missing validators became a known empty list")
		}
	}
	var changes []ValidatorChange
	_ = json.Unmarshal(s.Calls[4].Data, &changes)
	if changes[0].ValidatorsReported {
		t.Fatal("epoch-only record invented a validator-list observation")
	}
	fs, err := faults(raw([]any{map[string]any{"number": "0x0", "kind": "gap", "instance": testAddr, "what": "synthetic", "gapFrom": "0x0", "gapTo": "0x0"}}), 0, 0)
	if err != nil || len(fs) != 1 || !fs[0].BoundsKnown || *fs[0].GapFrom != "0x0" || *fs[0].GapTo != "0x0" {
		t.Fatal(fs, err)
	}
}

func TestNonAtomicHeadMovementIsRecordedAndContradictoryTransactionsAreRejected(t *testing.T) {
	a := fixture()
	v := resultMap(t, &a, len(a.Replies)-1)
	v["head"] = map[string]string{"number": "9007199254741001", "hash": "0x" + strings.Repeat("3", 64)}
	replaceResult(&a, len(a.Replies)-1, v)
	s, err := Normalize(a)
	if err != nil || s.Atomic || s.Before.Head == s.After.Head || s.Before.HeadHash == s.After.HeadHash {
		t.Fatalf("identity before=%+v after=%+v: %v", s.Before, s.After, err)
	}
	a = fixture()
	var env map[string]json.RawMessage
	_ = json.Unmarshal(a.Replies[2].Response, &env)
	var rows []map[string]any
	_ = json.Unmarshal(env["result"], &rows)
	other := map[string]any{}
	for k, value := range rows[0] {
		other[k] = value
	}
	other["path"] = []int{0}
	other["txHash"] = "0x" + strings.Repeat("3", 64)
	replaceResult(&a, 2, append(rows, other))
	if _, err := Normalize(a); err == nil {
		t.Fatal("one transaction coordinate has contradictory hashes")
	}
}

func TestLoadRejectsDuplicateFieldsAndPreservesSuppliedEnvelopeDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	a := fixture()
	data := raw(a)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, hash, err := Load(path)
	if err != nil || hash != digest(data) {
		t.Fatal(hash, err)
	}
	if _, err = Normalize(loaded); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"format":"x","format":"y"}`, string(data) + ` {}`, `{"unknown":"discard-me"}`} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Load(path); err == nil {
			t.Fatal("invalid archive accepted")
		}
	}
}

func TestFetchOnlyUsesPlannedReadOnlyMethodsAndRejectsIdentityChanges(t *testing.T) {
	a := fixture()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requests []struct {
			ID     int      `json:"id"`
			Method string   `json:"method"`
			Params []string `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&requests) != nil || len(requests) != 1 || calls >= len(a.Replies) {
			t.Error("unexpected request")
			w.WriteHeader(400)
			return
		}
		q := requests[0]
		want := a.Replies[calls]
		calls++
		if q.Method != want.Method || string(raw(q.Params)) != string(raw(want.Params)) {
			t.Errorf("request %s %v", q.Method, q.Params)
			w.WriteHeader(400)
			return
		}
		var env map[string]json.RawMessage
		_ = json.Unmarshal(want.Response, &env)
		_, _ = fmt.Fprintf(w, `[{"jsonrpc":"2.0","id":%d,"result":%s}]`, q.ID, env["result"])
	}))
	defer server.Close()
	c, err := client.New(server.URL, 5)
	if err != nil {
		t.Fatal(err)
	}
	c.Interval = time.Nanosecond
	got, err := Fetch(context.Background(), c, a.From, a.To, a.Instances, a.Proposals)
	if err != nil || calls != len(a.Replies) || got.EnvelopeOrigin != "client-reconstructed" {
		t.Fatal(calls, err)
	}
	if _, err := Normalize(got); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw(got)), server.URL) {
		t.Fatal("endpoint retained")
	}
	// A different source identity at the closing request invalidates the capture.
	v := resultMap(t, &a, len(a.Replies)-1)
	v["chainId"] = 9
	replaceResult(&a, len(a.Replies)-1, v)
	calls = 0
	if _, err := Fetch(context.Background(), c, a.From, a.To, a.Instances, a.Proposals); err == nil {
		t.Fatal("changed source accepted")
	}
}
