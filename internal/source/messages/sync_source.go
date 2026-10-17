package messages

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
)

// SyncEvidence addresses retained source metadata. Complete describes the
// available snapshot, never the correctness of the sync or consensus policy.
type SyncEvidence struct {
	Declaration OwnSourcePoint  `json:"declaration"`
	Request     *OwnSourcePoint `json:"request,omitempty"`
	Complete    bool            `json:"complete"`
}

type syncSourceRow struct {
	key      ownRecordKey
	point    OwnSourcePoint
	position *JournalPosition
	kind     string
	trace    *SyncTrace
	control  *SyncControl
}

type syncProjection struct {
	SyncTrace    *SyncTrace
	SyncControl  *SyncControl
	SyncEvidence *SyncEvidence
}

func syncRow(r Record) syncSourceRow {
	return syncSourceRow{ownKey(r), ownPoint(r), r.Journal, r.Type, r.SyncTrace, r.SyncControl}
}

// Legacy inputs need no additional in-memory index. Only a sync-capable
// snapshot rereads the closed metadata spool; payloads are never retained.
func readSyncSpool(ctx context.Context, spool *os.File) ([]syncSourceRow, error) {
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return nil, errSyncSource
	}
	decoder := json.NewDecoder(spool)
	var rows []syncSourceRow
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var r Record
		err := decoder.Decode(&r)
		if err == io.EOF {
			return rows, nil
		}
		if err != nil || len(rows) >= 1000000 {
			return nil, errSyncSource
		}
		rows = append(rows, syncRow(r))
	}
}

func projectSyncFrame(r *Record, x frameRecord, fields map[string]json.RawMessage) error {
	_, hasTrace := fields["sync_trace"]
	_, hasControl := fields["sync_control"]
	if !hasTrace && !hasControl && x.Type != "sync_trace" && x.Type != "sync_control" {
		return nil
	}
	if strings.ToLower(x.Node) != x.Node || x.JournalSegment == nil || x.JournalOffset == nil || *x.JournalOffset < 0 || x.Seq == nil || *x.Seq == 0 || x.Mono == nil || *x.Mono < 0 {
		return errSyncSource
	}
	r.Journal = &JournalPosition{number(*x.JournalSegment), strconv.FormatInt(*x.JournalOffset, 10)}
	if hasTrace {
		if x.Type != "sync_trace" && x.Type != "scheduler_trace" && x.Type != "cache_trace" {
			return errSyncSource
		}
		t, err := decodeSyncTrace(x.SyncTrace)
		if err != nil {
			return err
		}
		if x.ClockSource != "unavailable" || *x.Mono != 0 || x.Wall != "1970-01-01T00:00:00Z" {
			return errSyncSource
		}
		r.SyncTrace = t
		r.ClockSource, r.Wall, r.Mono = "unavailable", "", nil
	}
	if hasControl {
		if x.Type != "sync_control" {
			return errSyncSource
		}
		c, err := decodeSyncControl(x.SyncControl)
		if err != nil {
			return err
		}
		r.SyncControl = c
		r.ClockSource = "recorded"
	}
	if x.Type == "sync_trace" && !hasTrace || x.Type == "sync_control" && !hasControl {
		return errSyncSource
	}
	if x.Type == "sync_trace" || x.Type == "sync_control" {
		allowed := []string{"v", "type", "node", "run", "seq", "t_wall", "t_mono_ns", "journal_segment", "journal_offset", x.Type}
		if x.Type == "sync_trace" {
			allowed = append(allowed, "clock_source")
		}
		for name, raw := range fields {
			if !slices.Contains(allowed, name) || string(raw) == "null" {
				return errSyncSource
			}
		}
	}
	return nil
}

// Group frame files separately, but keep a journal writer across its segment
// files. Output always retains the original filename and original ordinal.
func finishSyncSources(rows []syncSourceRow, rawJournal, conflicted bool) (map[ownRecordKey]syncProjection, error) {
	out := map[ownRecordKey]syncProjection{}
	groups := map[ownScope][]syncSourceRow{}
	for _, r := range rows {
		scope := r.key.ownScope
		if rawJournal {
			scope.file = ""
		}
		groups[scope] = append(groups[scope], r)
	}
	for _, group := range groups {
		var declaration *syncSourceRow
		hasControls := false
		for i := range group {
			r := &group[i]
			if r.trace != nil {
				if declaration != nil || !syncTraceValid(r.trace) {
					return nil, errSyncSource
				}
				declaration = r
			}
			hasControls = hasControls || r.control != nil
		}
		if declaration == nil {
			if hasControls {
				return nil, errSyncSource
			}
			continue
		}
		if conflicted {
			return nil, errSyncSource
		}
		trace := declaration.trace
		complete := declaration.point.Seq == "1"
		inputs := map[string]syncSourceRow{}
		operations := map[string]bool{}
		positions := map[JournalPosition]bool{}
		var requests, processed, maxRequest, maxOperation, last uint64
		for _, r := range group {
			seq, ok := cacheUint(r.point.Seq)
			if !ok || seq == 0 {
				return nil, errSyncSource
			}
			if r.position == nil {
				if rawJournal || r.trace != nil || r.control != nil {
					return nil, errSyncSource
				}
			} else {
				if positions[*r.position] {
					return nil, errSyncSource
				}
				positions[*r.position] = true
			}
			if rawJournal && (seq != last+1 || seq == 0) {
				complete = false
			}
			last = seq
			if r.kind == "gap" {
				complete = false
			}
			c := r.control
			if c == nil {
				continue
			}
			if !syncControlValid(c, !rawJournal) {
				return nil, errSyncSource
			}
			request, _ := cacheUint(c.Request)
			if request == 0 || *c.SequenceExhausted {
				complete = false
			}
			if c.Stage == "requested" {
				requests++
				if request != 0 {
					if _, exists := inputs[c.Request]; exists {
						return nil, errSyncSource
					}
					inputs[c.Request] = r
					maxRequest = max(maxRequest, request)
				}
			} else {
				processed++
				op, _ := cacheUint(c.Operation)
				if op == 0 {
					complete = false
				} else {
					if operations[c.Operation] {
						return nil, errSyncSource
					}
					operations[c.Operation] = true
					maxOperation = max(maxOperation, op)
				}
				if c.Action != "none" && !*c.EventsAvailable {
					complete = false
				}
			}
		}
		if requests != maxRequest || processed != maxOperation {
			complete = false
		}
		for _, r := range group {
			c := r.control
			if c == nil || c.Stage != "processed" {
				continue
			}
			x, exists := inputs[c.Request]
			if !exists || *x.control.Syncing != *c.Syncing || *x.control.Success != *c.Success {
				complete = false
			}
		}
		if rawJournal {
			trace.Requests, trace.Operations, trace.Complete = number(requests), number(processed), cacheBool(complete)
		} else {
			wantRequests, _ := cacheUint(trace.Requests)
			wantOperations, _ := cacheUint(trace.Operations)
			if requests != wantRequests || processed != wantOperations || *trace.Complete && !complete {
				return nil, errSyncSource
			}
			complete = complete && *trace.Complete
		}
		for _, r := range group {
			if r.trace == nil && r.control == nil {
				continue
			}
			projection := syncProjection{SyncTrace: r.trace, SyncControl: r.control}
			if c := r.control; c != nil {
				evidence := &SyncEvidence{Declaration: declaration.point, Complete: complete}
				projection.SyncEvidence = evidence
				if c.Stage == "processed" {
					x, exists := inputs[c.Request]
					if rawJournal {
						c.RequestSource = &SyncRequestSource{Available: cacheBool(false)}
						if complete && exists {
							c.RequestSource = &SyncRequestSource{Available: cacheBool(true), Seq: x.point.Seq, Segment: x.position.Segment, Offset: x.position.Offset}
						}
					} else if *c.RequestSource.Available != complete {
						return nil, errSyncSource
					}
					if *c.RequestSource.Available {
						if !exists || x.position == nil || c.RequestSource.Seq != x.point.Seq || c.RequestSource.Segment != x.position.Segment || c.RequestSource.Offset != x.position.Offset {
							return nil, errSyncSource
						}
						point := x.point
						evidence.Request = &point
					}
				}
			}
			out[r.key] = projection
		}
	}
	return out, nil
}
