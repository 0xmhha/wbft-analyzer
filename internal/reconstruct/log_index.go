package reconstruct

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"sort"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

type indexedLog struct {
	event   logs.Event
	payload *logs.PayloadWitness
	at      time.Time
}

type executionLog struct {
	rows     []indexedLog
	stats    logs.Stats
	payloads map[payloadKey][]indexedLog
}

type payloadKey struct{ run, code, sha string }

func executionLogIndex(ctx context.Context, m Manifest) (*executionLog, error) {
	raw, err := snapshot(ctx, m.Log, 256<<20)
	if err != nil {
		return nil, err
	}
	profile, err := logs.LoadProfile("gstable@740526d03")
	if err != nil {
		return nil, err
	}
	index := &executionLog{}
	cursor := bufio.NewScanner(bytes.NewReader(raw))
	cursor.Buffer(make([]byte, 64<<10), 4<<20)
	var line int64
	index.stats, err = logs.Read(ctx, bytes.NewReader(raw), profile, m.Node, "log", func(e logs.Event) error {
		for line < e.Line {
			if !cursor.Scan() {
				return errors.New("reconstruction log coordinate unavailable")
			}
			line++
		}
		if address := field(e, "address"); address != "" && address != m.Node {
			return errors.New("reconstruction log node identity differs")
		}
		payload := logs.MessagePayload(cursor.Bytes())
		switch e.Record.Kind {
		case event.TimerArm, event.TimerFire, event.EngineStart, event.EngineStop:
		default:
			if payload == nil {
				return nil
			}
		}
		if len(index.rows) >= MaxProcessingRecords {
			return errors.New("reconstruction execution log exceeds 100000 records")
		}
		at, _ := time.Parse(time.RFC3339Nano, e.Wall)
		index.rows = append(index.rows, indexedLog{event: e, payload: payload, at: at})
		return nil
	})
	if err != nil {
		return nil, err
	}
	// This order is for interval lookup only. Input processing order remains
	// the observation ordinals; a clock sort never becomes an input schedule.
	sort.SliceStable(index.rows, func(i, j int) bool { return index.rows[i].at.Before(index.rows[j].at) })
	index.payloads = map[payloadKey][]indexedLog{}
	for _, row := range index.rows {
		if p := row.payload; p != nil && p.Status == "decoded" && p.Signer == m.Node {
			key := payloadKey{row.event.Run, p.Code, p.SHA256}
			index.payloads[key] = append(index.payloads[key], row)
		}
	}
	return index, nil
}

func (l *executionLog) window(source inputobs.Input, run string) ([]indexedLog, error) {
	begin, firstErr := time.Parse(time.RFC3339Nano, source.BeginWall)
	end, lastErr := time.Parse(time.RFC3339Nano, source.EndWall)
	if firstErr != nil || lastErr != nil || end.Before(begin) || run == "" {
		return nil, refusedBinding("processing_log_window_unbound")
	}
	first := sort.Search(len(l.rows), func(i int) bool { return !l.rows[i].at.Before(begin) })
	last := sort.Search(len(l.rows), func(i int) bool { return l.rows[i].at.After(end) })
	rows := []indexedLog{}
	for _, row := range l.rows[first:last] {
		if row.event.Run == run {
			rows = append(rows, row)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].event.Line < rows[j].event.Line })
	return rows, nil
}

func eventsOf(rows []indexedLog) []logs.Event {
	entries := make([]logs.Event, len(rows))
	for i, row := range rows {
		entries[i] = row.event
	}
	return entries
}
