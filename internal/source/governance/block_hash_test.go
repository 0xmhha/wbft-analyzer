package governance

import (
	"encoding/json"
	"strings"
	"testing"
)

func responseRows(t *testing.T, a Archive, call int) []map[string]any {
	t.Helper()
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(a.Replies[call].Response, &env) != nil {
		t.Fatal("envelope")
	}
	var rows []map[string]any
	if json.Unmarshal(env.Result, &rows) != nil {
		t.Fatal("rows")
	}
	return rows
}
func requireNormalizedHash(t *testing.T, value any, want string) {
	t.Helper()
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw(value), &fields) != nil {
		t.Fatal(value)
	}
	v, ok := fields["block_hash"]
	if want == "" {
		if ok {
			t.Fatalf("invented hash: %s", raw(value))
		}
		return
	}
	var got string
	if !ok || json.Unmarshal(v, &got) != nil || got != want {
		t.Fatalf("record hash lost: %s; want %s", raw(value), want)
	}
}
func TestStoredBlockHashesSurviveEveryGovernanceScope(t *testing.T) {
	a := fixture()
	hash := "0x" + strings.Repeat("AB", 32)
	alterOperation(t, &a, func(op map[string]any) { op["blockHash"] = hash })
	change := responseRows(t, a, 4)
	change[0]["blockHash"] = hash
	op := responseRows(t, a, 2)[0]
	op["number"] = a.To
	change[0]["ops"] = []any{op}
	replaceResult(&a, 4, change)
	proposal := resultMap(t, &a, 6)
	older := proposal["ops"].([]any)[0].(map[string]any)
	older["blockHash"] = hash
	replaceResult(&a, 6, proposal)
	snap, err := Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	var ops []Operation
	_ = json.Unmarshal(snap.Calls[2].Data, &ops)
	requireNormalizedHash(t, ops[0], strings.ToLower(hash))
	var changes []ValidatorChange
	_ = json.Unmarshal(snap.Calls[4].Data, &changes)
	requireNormalizedHash(t, changes[0], strings.ToLower(hash))
	requireNormalizedHash(t, changes[0].Ops[0], strings.ToLower(hash))
	var history ProposalHistory
	_ = json.Unmarshal(snap.Calls[6].Data, &history)
	requireNormalizedHash(t, history.Ops[0], strings.ToLower(hash))
	if ops[0].TxHash != testHash || ops[0].Number != a.From || history.Ops[0].Number != "0x1" || ops[0].ExecutingProposalID != nil {
		t.Fatal("source semantics changed")
	}
}
func TestLegacyNullAndZeroRecordHashesStayUnknown(t *testing.T) {
	for _, value := range []any{nil, "0x" + strings.Repeat("0", 64)} {
		a := fixture()
		alterOperation(t, &a, func(op map[string]any) { op["blockHash"] = value })
		rows := responseRows(t, a, 4)
		rows[0]["blockHash"] = value
		replaceResult(&a, 4, rows)
		snap, err := Normalize(a)
		if err != nil {
			t.Fatal(err)
		}
		var ops []Operation
		_ = json.Unmarshal(snap.Calls[2].Data, &ops)
		requireNormalizedHash(t, ops[0], "")
		var changes []ValidatorChange
		_ = json.Unmarshal(snap.Calls[4].Data, &changes)
		requireNormalizedHash(t, changes[0], "")
	}
}
func TestMalformedOrConflictingStoredBlockHashesAreRejected(t *testing.T) {
	for name, change := range map[string]func(*Archive){
		"short operation hash": func(a *Archive) { alterOperation(t, a, func(op map[string]any) { op["blockHash"] = "0x12" }) },
		"wrong operation type": func(a *Archive) { alterOperation(t, a, func(op map[string]any) { op["blockHash"] = 12 }) },
		"operation alias":      func(a *Archive) { alterOperation(t, a, func(op map[string]any) { op["BlockHash"] = testHash }) },
		"short record hash": func(a *Archive) {
			rows := responseRows(t, *a, 4)
			rows[0]["blockHash"] = "0x12"
			replaceResult(a, 4, rows)
		},
		"record alias": func(a *Archive) {
			rows := responseRows(t, *a, 4)
			rows[0]["BlockHash"] = testHash
			replaceResult(a, 4, rows)
		},
		"two hashes at one index": func(a *Archive) {
			rows := responseRows(t, *a, 2)
			rows[0]["blockHash"] = testHash
			other := map[string]any{}
			for k, v := range rows[0] {
				other[k] = v
			}
			other["tx"] = 1
			other["blockHash"] = "0x" + strings.Repeat("3", 64)
			replaceResult(a, 2, []any{rows[0], other})
		},
		"nested record mismatch": func(a *Archive) {
			rows := responseRows(t, *a, 4)
			rows[0]["blockHash"] = testHash
			op := responseRows(t, *a, 2)[0]
			op["number"] = a.To
			op["blockHash"] = "0x" + strings.Repeat("3", 64)
			rows[0]["ops"] = []any{op}
			replaceResult(a, 4, rows)
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := fixture()
			change(&a)
			if _, err := Normalize(a); err == nil {
				t.Fatal("invalid stored hash context accepted")
			}
		})
	}
}

func TestMissingNestedRecordHashesAreNeverBackfilled(t *testing.T) {
	for _, parentKnown := range []bool{false, true} {
		a := fixture()
		rows := responseRows(t, a, 4)
		op := responseRows(t, a, 2)[0]
		op["number"] = a.To
		if parentKnown {
			rows[0]["blockHash"] = testHash
		} else {
			op["blockHash"] = testHash
		}
		rows[0]["ops"] = []any{op}
		replaceResult(&a, 4, rows)
		snap, err := Normalize(a)
		if err != nil {
			t.Fatal(err)
		}
		var changes []ValidatorChange
		_ = json.Unmarshal(snap.Calls[4].Data, &changes)
		parent, child := "", testHash
		if parentKnown {
			parent, child = testHash, ""
		}
		requireNormalizedHash(t, changes[0], parent)
		requireNormalizedHash(t, changes[0].Ops[0], child)
	}
}
