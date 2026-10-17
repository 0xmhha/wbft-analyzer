package messages

import (
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft/observe/journal"
)

type journalSyncState struct {
	run      string
	versions map[string]uint64
}

func newJournalSyncState() *journalSyncState {
	return &journalSyncState{versions: map[string]uint64{}}
}

func (s *journalSyncState) project(r *Record, rec journal.Record) error {
	first := false
	if b, ok := rec.Body.(*journal.SegmentRec); ok {
		old, seen := s.versions[b.Run]
		if b.Core.SyncTrace > journal.SyncTraceVersion || seen && old != b.Core.SyncTrace || seen && s.run != b.Run && (old != 0 || b.Core.SyncTrace != 0) {
			return errSyncSource
		}
		first = !seen
		s.versions[b.Run] = b.Core.SyncTrace
		s.run = b.Run
	}
	version := s.versions[s.run]
	if version == 0 {
		if _, ok := rec.Body.(*journal.SyncRec); ok {
			return errSyncSource
		}
		return nil
	}
	if r.Offset == nil || *r.Offset < 0 {
		return errSyncSource
	}
	segment, err := strconv.ParseUint(strings.TrimSuffix(r.File, ".wal"), 10, 64)
	if err != nil {
		return errSyncSource
	}
	r.Journal = &JournalPosition{number(segment), strconv.FormatInt(*r.Offset, 10)}
	r.syncJournal = true
	switch b := rec.Body.(type) {
	case *journal.SegmentRec:
		if first {
			r.SyncTrace = &SyncTrace{Version: number(version), Requests: "0", Operations: "0", Complete: cacheBool(false), EventCursor: "next_sequence"}
			r.ClockSource, r.Mono, r.Wall = "unavailable", nil, ""
		}
	case *journal.SyncRec:
		r.Type = "sync_control"
		r.ClockSource = "recorded"
		r.Mono = signed(int64(b.Mono))
		r.Wall = time.Unix(0, b.WallNs).UTC().Format(time.RFC3339Nano)
		r.SyncControl = &SyncControl{Stage: b.Stage, Request: number(b.Request), Operation: number(b.Operation), Syncing: cacheBool(b.Syncing), Success: cacheBool(b.Success), FirstBefore: cacheBool(b.FirstBefore), FirstAfter: cacheBool(b.FirstAfter), RunningBefore: cacheBool(b.RunningBefore), RunningAfter: cacheBool(b.RunningAfter), Action: b.Action, Failed: cacheBool(b.Failed), EventsAvailable: cacheBool(b.EventsAvailable), EventBefore: number(b.EventBefore), EventAfter: number(b.EventAfter), SequenceExhausted: cacheBool(b.SequenceExhausted)}
		if b.Stage == "processed" {
			r.SyncControl.RequestSource = &SyncRequestSource{Available: cacheBool(false)}
		}
		if !syncControlValid(r.SyncControl, false) {
			return errSyncSource
		}
	}
	return nil
}
