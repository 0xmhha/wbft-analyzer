package messages

import (
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/observe/event"
)

// UnassociatedEvidence preserves message observations excluded by execution
// association. State/timer records are source coverage, not missing messages.
func UnassociatedEvidence(records []source.Record, events []logs.Event, selectedRecords []source.Record, selectedEvents []logs.Event) ([]Issue, []Issue) {
	rRuns, eRuns := map[[2]string]bool{}, map[[2]string]bool{}
	for _, r := range selectedRecords {
		rRuns[[2]string{r.Node, r.Run}] = true
	}
	for _, e := range selectedEvents {
		eRuns[[2]string{e.Node, e.Run}] = true
	}
	rs, es := []Issue{}, []Issue{}
	for _, r := range records {
		if r.Type == "frame" && !rRuns[[2]string{r.Node, r.Run}] {
			rs = append(rs, Issue{recordSource(r), "unassociated_run"})
		}
	}
	for _, e := range events {
		if !eRuns[[2]string{e.Node, e.Run}] && (e.Record.Kind == event.Send || e.Record.Kind == event.MsgOutcome) {
			es = append(es, Issue{eventSource(e), "unassociated_run"})
		}
	}
	return rs, es
}
