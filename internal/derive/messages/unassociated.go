package messages

import (
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

// UnassociatedEvidence preserves message observations excluded by execution
// association. State/timer records are source coverage, not missing messages.
func UnassociatedEvidence(records []source.Record, events []logs.Event, selectedRecords []source.Record, selectedEvents []logs.Event) ([]Issue, []Issue) {
	rRuns := map[[2]string]bool{}
	type eventPointer struct {
		input, node, run string
		line             int64
	}
	ePointers := map[eventPointer]bool{}
	for _, r := range selectedRecords {
		rRuns[[2]string{r.Node, r.Run}] = true
	}
	for _, e := range selectedEvents {
		ePointers[eventPointer{e.Input, e.Node, e.Run, e.Line}] = true
	}
	rs, es := []Issue{}, []Issue{}
	for _, r := range records {
		if r.Type == "frame" && !rRuns[[2]string{r.Node, r.Run}] {
			rs = append(rs, Issue{recordSource(r), "unassociated_run"})
		}
	}
	for _, e := range events {
		if !ePointers[eventPointer{e.Input, e.Node, e.Run, e.Line}] && messageEvent(e) {
			es = append(es, Issue{eventSource(e), "unassociated_run"})
		}
	}
	return rs, es
}
