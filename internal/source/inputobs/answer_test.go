package inputobs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func answerFixture() []map[string]any {
	base := observationFixture()
	sum := sha256.Sum256([]byte{1, 2, 3})
	methods := []map[string]any{
		{"method": "head", "outcome": "available", "head_proposer": "0x" + strings.Repeat("1", 40)},
		{"method": "validators_at", "outcome": "available", "argument_sha256": strings.Repeat("7", 64)},
		{"method": "verify", "outcome": "accepted", "duration_ns": "0"},
		{"method": "bad_block", "subject_hash": "0x" + strings.Repeat("8", 64), "is_bad": false},
		{"method": "commit_header", "outcome": "accepted", "argument_sha256": strings.Repeat("9", 64)},
	}
	for _, row := range methods {
		row["type"], row["ordinal"], row["instance"] = "answer", "2", "1"
		if row["method"] != "bad_block" {
			row["payload_available"], row["payload"], row["payload_sha256"] = true, "0x010203", hex.EncodeToString(sum[:])
		}
	}
	rows := append(append(append([]map[string]any{}, base[:4]...), methods...), base[4:]...)
	stampObservations(rows)
	return rows
}

func TestInputAnswersKeepActualOrderCoordinatesAndPrivateBytes(t *testing.T) {
	c, err := Read(t.Context(), bytes.NewReader(encodeObservations(t, answerFixture())))
	if err != nil || !c.Complete || len(c.Inputs[1].Answers) != 5 {
		t.Fatal(c, err)
	}
	want := []string{"head", "validators_at", "verify", "bad_block", "commit_header"}
	for i, answer := range c.Inputs[1].Answers {
		if answer.Method != want[i] || answer.Line != int64(5+i) || answer.Mono == "" || answer.Wall == "" {
			t.Fatal(answer)
		}
		if i != 3 && !bytes.Equal(answer.Payload, []byte{1, 2, 3}) {
			t.Fatal("lost original application bytes", answer)
		}
	}
	encoded, err := json.Marshal(c)
	if err != nil || bytes.Contains(encoded, []byte("0x010203")) || bytes.Contains(encoded, []byte(`"payload":`)) {
		t.Fatal("application bytes escaped into metadata", err)
	}
}

func TestInputAnswersRefuseOrphansContradictionsAndForeignFields(t *testing.T) {
	for _, mutate := range []func([]map[string]any){
		func(r []map[string]any) { r[4]["ordinal"] = "1" },
		func(r []map[string]any) { r[4]["instance"] = "2" },
		func(r []map[string]any) { r[4]["method"] = "invented" },
		func(r []map[string]any) { r[4]["payload"] = "0x040506" },
		func(r []map[string]any) { r[4]["head_proposer"] = "unknown" },
		func(r []map[string]any) { r[4]["is_bad"] = false },
		func(r []map[string]any) { r[6]["duration_ns"] = "-0" },
		func(r []map[string]any) { r[6]["duration_ns"] = "9223372036854775808" },
		func(r []map[string]any) { r[6]["outcome"] = "inferred" },
		func(r []map[string]any) { delete(r[7], "is_bad") },
		func(r []map[string]any) { r[7]["payload_available"] = true },
		func(r []map[string]any) { r[8]["argument_sha256"] = "unbound" },
		func(r []map[string]any) { r[8]["duration_ns"] = "0" },
		func(r []map[string]any) { r[8]["source_error"] = "PRIVATE_VALUE" },
	} {
		rows := answerFixture()
		mutate(rows)
		c, err := Read(t.Context(), bytes.NewReader(encodeObservations(t, rows)))
		if err == nil || c.Node != "" || len(c.Inputs) != 0 {
			t.Fatal("invalid application answer exposed a partial capture", c, err)
		}
	}
}

func TestMissingApplicationAnswerBytesStayUnavailable(t *testing.T) {
	for _, method := range []string{"head", "validators_at", "verify", "commit_header"} {
		r := answerFixture()
		for _, row := range r {
			if row["method"] != method {
				continue
			}
			row["payload_available"] = false
			delete(row, "payload")
			delete(row, "payload_sha256")
		}
		c, err := Read(t.Context(), bytes.NewReader(encodeObservations(t, r)))
		if err != nil || c.Complete || !hasGap(c, "input_payload_unavailable") {
			t.Fatal(method, c, err)
		}
	}
}

func TestApplicationAnswerBoundAndSignedFutureDuration(t *testing.T) {
	r := answerFixture()
	r[6]["outcome"], r[6]["duration_ns"] = "future", "-7"
	if c, err := Read(t.Context(), bytes.NewReader(encodeObservations(t, r))); err != nil || c.Inputs[1].Answers[2].DurationNS != "-7" {
		t.Fatal(c, err)
	}
	for _, count := range []int{16, 17} {
		base := observationFixture()
		rows := append([]map[string]any{}, base[:4]...)
		for i := 0; i < count; i++ {
			row := map[string]any{"type": "answer", "ordinal": "2", "instance": "1", "method": "bad_block", "subject_hash": "0x" + strings.Repeat("8", 64), "is_bad": false}
			rows = append(rows, row)
		}
		rows = append(rows, base[4:]...)
		stampObservations(rows)
		raw := encodeObservations(t, rows)
		c, err := read(t.Context(), bytes.NewReader(raw), len(raw), 2)
		if count == 16 && (err != nil || !c.Complete || len(c.Inputs[1].Answers) != count) || count == 17 && (err == nil || len(c.Inputs) != 0) {
			t.Fatal(count, c, err)
		}
	}
}
