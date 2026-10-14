package whatif

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/crypto/keccak"
)

func TestInspectEvidenceReplaysCompleteSourceAndBindsQuestionOutput(t *testing.T) {
	validators := make([]sim.Validator, 4)
	for index := range validators {
		var err error
		validators[index], err = sim.NewValidator(keccak.Sum256Bytes([]byte("synthetic-timer-evidence-" + strconv.Itoa(index))))
		if err != nil {
			t.Fatal(err)
		}
	}
	var links []sim.Link
	for i, a := range validators {
		for j, b := range validators {
			if i != j {
				links = append(links, sim.Link{From: a.Address(), To: b.Address(), Delay: []time.Duration{10 * time.Millisecond}})
			}
		}
	}
	journalRoot := t.TempDir()
	result, err := sim.Run(context.Background(), sim.Scenario{Name: "synthetic-timer-evidence", Seed: 4, Validators: validators, Links: links, Until: sim.Stop{Height: 3, Duration: time.Minute}}, sim.Output{JournalDir: journalRoot})
	if err != nil || len(result.Violations) != 0 {
		t.Fatal(err, result.Violations)
	}
	blocks, err := sim.NewChainSource(result.Chain)
	if err != nil {
		t.Fatal(err)
	}
	checked, questions, answers := 0, 0, 0
	for _, files := range result.Journals {
		dir := t.TempDir()
		for name, raw := range files {
			if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		evidence, err := InspectEvidence(context.Background(), dir, blocks)
		if err != nil {
			t.Fatal(err)
		}
		if len(evidence.sources) == 0 {
			t.Fatal("source positions missing")
		}
		for question := range evidence.questions {
			if !evidence.sources[question.Source] {
				t.Fatal("question acquired unknown source")
			}
		}
		var output bytes.Buffer
		seconds := "2"
		if err := ServeTimed(context.Background(), dir, filepath.Join(journalRoot, "chain.rlp"), 1, Policy{Request: &seconds}, json.NewEncoder(&output)); err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(&output)
		var previous uint64
		terminal := false
		for decoder.More() {
			var raw json.RawMessage
			if decoder.Decode(&raw) != nil {
				t.Fatal("malformed helper output")
			}
			var header struct {
				Type string `json:"type"`
				Code string `json:"code"`
			}
			if json.Unmarshal(raw, &header) != nil {
				t.Fatal("malformed helper header")
			}
			switch header.Type {
			case "timed_step":
				step, err := DecodeStep(raw, previous)
				if err != nil {
					t.Fatal("invalid timed helper step", err, string(raw))
				}
				if err = evidence.Validate(step, previous); err != nil {
					t.Fatal("unbound source evidence", err, string(raw))
				}
				previous++
			case "timed_done":
				terminal = true
			case "error":
				if header.Code != "signing_unavailable" && header.Code != "env_exhausted" && header.Code != "reservation_unavailable" {
					t.Fatal("unexpected experiment error", string(raw))
				}
				terminal = true
			default:
				t.Fatal("unexpected helper reply", string(raw))
			}
		}
		if !terminal || previous == 0 {
			t.Fatal("missing experiment terminal/steps")
		}
		checked++
		questions += len(evidence.questions)
		answers += len(evidence.recorded)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err = InspectEvidence(ctx, dir, blocks); err == nil {
			t.Fatal("cancelled inspection continued")
		}
	}
	if checked != 4 || questions == 0 || answers == 0 {
		t.Fatal(checked, questions, answers)
	}
}
