package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
)

func TestRecordedMessageRequestAndCandidateJSONContract(t *testing.T) {
	s := loadSpec(t)
	body := s.Paths["/v1/networks/{net}/datasets/{dataset}/scenario-jobs"]["post"].RequestBody.Content["application/json"].Schema
	ref := `{"input":"frames-a","file":"frames-a.jsonl","ordinal":"9007199254740993","model_occurrence":"18446744073709551615"}`
	drop := `{"source_id":"source","change":{"kind":"drop_message","from_ns":0,"to_ns":120000000000,"messages":[` + ref + `]}}`
	swap := `{"source_id":"source","change":{"kind":"swap_messages","from_ns":0,"to_ns":120000000000,"messages":[` + ref + `,` + strings.Replace(ref, "9007199254740993", "9007199254740994", 1) + `]}}`
	check := func(raw string) error {
		var value any
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		return s.check(value, body, "$")
	}
	for _, raw := range []string{drop, swap} {
		var request ScenarioRequest
		if err := json.Unmarshal([]byte(raw), &request); err != nil {
			t.Fatal(err)
		}
		if err := check(raw); err != nil {
			t.Fatal(raw, err)
		}
		if request.Change.Messages[0].Ordinal != 9007199254740993 || request.Change.Messages[0].Occurrence != ^uint64(0) {
			t.Fatal("request rounded", request)
		}
	}
	for _, raw := range []string{
		strings.Replace(drop, `"ordinal":"9007199254740993"`, `"ordinal":9007199254740993`, 1),
		strings.Replace(drop, `"model_occurrence":"18446744073709551615"`, `"model_occurrence":null`, 1),
		strings.Replace(drop, `"model_occurrence":"18446744073709551615"`, `"model_occurrence":"01"`, 1),
		strings.Replace(drop, `"ordinal":"9007199254740993"`, `"ordinal":"0"`, 1),
		strings.Replace(drop, `"messages":[`, `"effective_selector":{},"messages":[`, 1),
		strings.Replace(drop, `"drop_message"`, `"swap_messages"`, 1),
	} {
		var request ScenarioRequest
		if json.Unmarshal([]byte(raw), &request) == nil {
			t.Fatal("runtime accepted invalid selection", raw)
		}
		if check(raw) == nil {
			t.Fatal("document accepted invalid selection", raw)
		}
	}
	page := ScenarioMessagePage{SourceSHA256: strings.Repeat("a", 64), Verification: "metadata_projection_only_full_frame_and_signature_validation_on_queue", Messages: []scenario.RecordedMessageEvidence{{Input: "frames-a", File: "frames-a.jsonl", Ordinal: 9007199254740993, Height: "18446744073709551617", Round: "1208925819614629174706176"}}}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"ordinal":"9007199254740993"`)) {
		t.Fatal("response rounded", string(raw))
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	answer, err := s.answerSchema("GET", "/v1/networks/1/datasets/2/scenario-messages", 200)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.check(value, answer, "$"); err != nil {
		t.Fatal(err)
	}
}
