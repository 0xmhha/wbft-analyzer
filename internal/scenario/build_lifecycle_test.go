package scenario

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

func lifecycleRecord(kind event.Kind, line, mono int64, id, status string) logs.Event {
	clock := strconv.FormatInt(mono, 10)
	fields := map[string]any{"number": "1", "build_id": id, "wait_ns": "1000000000"}
	if status != "" {
		fields["status"] = status
	}
	if status == "submitted" {
		fields["hash"] = "0x" + strings.Repeat("a", 64)
	}
	return logs.Event{Node: "a", Input: "i", Run: "r", Profile: logs.EventProfile, Line: line, Mono: &clock, Record: event.Record{Kind: kind, View: &event.View{Seq: "1", Round: "0"}, Fields: fields}}
}
func successfulLifecycle(id string, line, offset int64) []logs.Event {
	return []logs.Event{
		lifecycleRecord(event.BuildRequest, line, offset, id, ""),
		lifecycleRecord(event.BuildHandover, line+1, offset, id, ""),
		lifecycleRecord(event.BuildStarted, line+2, offset+1100000000, id, ""),
		lifecycleRecord(event.BuildFinished, line+3, offset+1120000000, id, "submitted"),
	}
}
func TestExactBuildIDsSeparateRepeatedSameHeightWithoutAssumedWait(t *testing.T) {
	xs := append(successfulLifecycle("build-1", 1, 0), successfulLifecycle("build-2", 5, 2000000000)...)
	got, err := FitAppTiming(xs)
	if err != nil || len(got.Build) != 2 || got.Unproved != 0 || got.Unsupported != 0 || len(got.Outcomes) != 2 {
		t.Fatal(got, err)
	}
	for i, sample := range got.Build {
		if sample.Nanoseconds != int64(20*time.Millisecond) || sample.Definition != "assembly_to_submission" || sample.BuildID != "build-"+strconv.Itoa(i+1) || sample.FromLine != int64(i*4+3) {
			t.Fatal("assumed wait or nearest request used", got)
		}
	}
}
func TestKnownBuildReplacementRetainsOutcomeAndIncompleteSimulatorModel(t *testing.T) {
	xs := []logs.Event{lifecycleRecord(event.BuildRequest, 1, 0, "build-1", ""), lifecycleRecord(event.BuildHandover, 2, 0, "build-1", ""), lifecycleRecord(event.BuildFinished, 3, 10, "build-1", "replaced")}
	xs = append(xs, successfulLifecycle("build-2", 4, 100)...)
	got, err := FitAppTiming(xs)
	if err != nil || len(got.Build) != 1 || got.Unproved != 0 || got.Unsupported != 1 || got.Outcomes[0].Status != "replaced" || got.Outcomes[0].StartLine != 0 {
		t.Fatal("known cancellation became success or missing evidence", got, err)
	}
}
func TestExactBuildTimingRejectsMissingDuplicateCrossRunAndClockEndpoints(t *testing.T) {
	for _, change := range []string{"missing", "duplicate", "run", "clock", "view", "handover", "request", "hash"} {
		xs := successfulLifecycle("build-1", 1, 0)
		switch change {
		case "missing":
			xs = append(xs[:2], xs[3])
		case "duplicate":
			xs = append(xs, xs[2])
		case "run":
			xs[3].Run = "other"
		case "clock":
			clock := "1099999999"
			xs[3].Mono = &clock
		case "view":
			xs[3].Record.View = &event.View{Seq: "2", Round: "0"}
		case "handover":
			xs = append(xs[:1], xs[2:]...)
		case "request":
			xs = append(xs, lifecycleRecord(event.BuildRequest, 5, 0, "", ""))
		case "hash":
			delete(xs[3].Record.Fields, "hash")
		}
		got, err := FitAppTiming(xs)
		if err != nil || got.Unproved == 0 {
			t.Fatal("incomplete lifecycle accepted", change, got, err)
		}
	}
}
func TestLifecycleScopeExcludesWholeOutOfRangeRequestWithoutDeletingOriginal(t *testing.T) {
	xs := successfulLifecycle("build-1", 1, 0)
	for i := range xs {
		xs[i].Record.View = &event.View{Seq: "11", Round: "0"}
		xs[i].Record.Fields["number"] = "11"
	}
	selected, counts, err := ScopeApplication(xs, 1, 10)
	if err != nil || len(selected) != 0 || counts.AppExcluded != 4 || len(xs) != 4 {
		t.Fatal(selected, counts, err)
	}
}
