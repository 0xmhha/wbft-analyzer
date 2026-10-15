package scenariojob

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/consensus/inputlog"
)

func processingPlanFixture() (scenario.Input, reexec.Plan) {
	source := scenario.Input{ID: "journal", Kind: "journal", Node: "0x" + strings.Repeat("1", 40), SHA256: strings.Repeat("a", 64)}
	entry := "9007199254740993"
	row := reexec.Step{Ordinal: 2, File: "00000000000000000000.wal", Run: "writer", Engine: "1", Number: "2", Height: "1", Input: inputlog.KindCapturedMessage, InputVia: "peer", Phase: "COMMIT", Completeness: "complete", EntryMono: &entry, Mono: "9007199254740994"}
	return source, reexec.Plan{From: 1, To: 2, Input: messages.Prepared{Summary: messages.Summary{ID: source.ID, Kind: source.Kind, Node: source.Node, SHA256: source.SHA256}}, Steps: []reexec.Step{row}}
}

func TestProcessingTimingsKeepMeasuredZeroLargeClocksAndSource(t *testing.T) {
	source, plan := processingPlanFixture()
	zero := "0"
	row := plan.Steps[0]
	row.Ordinal, row.Number, row.Input, row.InputVia, row.EntryMono, row.Mono = 3, "3", inputlog.KindRequest, "app", &zero, "0"
	plan.Steps = append(plan.Steps, row)
	got, err := processingTimingsFromPlan(source, 1, 2, time.Second, plan)
	if err != nil || got.Status != "complete" || len(got.Samples) != 2 || got.Samples[0].Nanoseconds != 1 || got.Samples[1].Nanoseconds != 0 || got.Samples[0].Code != uint64(codec.CodeCommit) || got.Samples[0].Kind != inputlog.KindMessage || !reflect.DeepEqual(source, got.Source) {
		t.Fatal("measured timing or capture class lost", got, err)
	}
	if got.Samples[0].EntryMono != "9007199254740993" || got.Samples[0].Point.Run != "writer" || got.Samples[0].Point.Ordinal != 2 || got.Scope != "recorded_core_head_plus_one" {
		t.Fatal("timing or source coordinate rounded", got)
	}
	*plan.Steps[0].EntryMono = "7"
	if got.Samples[0].EntryMono != "9007199254740993" {
		t.Fatal("source metadata aliases caller memory")
	}
}

func TestProcessingTimingsKeepUnknownEntryAndReplayExclusions(t *testing.T) {
	source, plan := processingPlanFixture()
	plan.Steps[0].EntryMono = nil
	for i, kind := range []string{inputlog.KindStart, inputlog.KindStop, inputlog.KindRequest} {
		row := plan.Steps[0]
		row.Ordinal, row.Input, row.InputVia = int64(i+3), kind, "wal"
		plan.Steps = append(plan.Steps, row)
	}
	got, err := processingTimingsFromPlan(source, 1, 2, time.Second, plan)
	if err != nil || got.Status != "partial" || len(got.Samples) != 0 || len(got.Excluded) != 4 || got.Excluded[0].Reason != "measured_entry_unavailable" || got.Excluded[3].Reason != "replay_or_warmup_not_service_costed" {
		t.Fatal("historical completion substituted for entry", got, err)
	}
}

func TestProcessingTimingsRejectUnprovedIntervalsAndIdentities(t *testing.T) {
	for _, mutate := range []func(*reexec.Step){
		func(s *reexec.Step) { s.Completeness = "partial" },
		func(s *reexec.Step) { s.InputVia = "unknown" },
		func(s *reexec.Step) { s.Engine = "0" },
		func(s *reexec.Step) { s.Number = "0" },
		func(s *reexec.Step) { s.Mono = "2" },
		func(s *reexec.Step) { s.Mono = "9007200254740994" },
		func(s *reexec.Step) { s.Phase = "unknown" },
	} {
		source, plan := processingPlanFixture()
		mutate(&plan.Steps[0])
		got, err := processingTimingsFromPlan(source, 1, 2, time.Second, plan)
		if err != nil || got.Status != "partial" || len(got.Samples) != 0 || len(got.Excluded) != 1 {
			t.Fatal("unproved interval became a sample", got, err)
		}
	}
	for _, mutate := range []func(*scenario.Input, *reexec.Plan){
		func(s *scenario.Input, p *reexec.Plan) { s.SHA256 = strings.Repeat("z", 64) },
		func(s *scenario.Input, p *reexec.Plan) { p.Input.Summary.SHA256 = strings.Repeat("b", 64) },
		func(s *scenario.Input, p *reexec.Plan) { p.From++ },
		func(s *scenario.Input, p *reexec.Plan) { p.JournalIssue = "journal_gap" },
		func(s *scenario.Input, p *reexec.Plan) { p.Steps = append(p.Steps, p.Steps[0]) },
	} {
		source, plan := processingPlanFixture()
		mutate(&source, &plan)
		if _, err := processingTimingsFromPlan(source, 1, 2, time.Second, plan); err == nil {
			t.Fatal("changed source identity or duplicate coordinates accepted")
		}
	}
}
