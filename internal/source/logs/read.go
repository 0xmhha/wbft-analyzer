package logs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft/observe/event"
)

// Event stamps the shared WBFT record with its log source. ViewInferred
// means a missing view was carried from the last round of this engine run.
type Event struct {
	// Mono is absent in logs; event sources may supply their process clock.
	Mono                                   *string
	Record                                 event.Record
	Node, Input, Run, Wall, Level, Profile string
	Line                                   int64
	ViewInferred                           bool
}
type Stats struct {
	MonotonicRegressions int64  `json:"monotonic_regressions,omitempty"`
	SequenceGaps         int64  `json:"sequence_gaps,omitempty"`
	Lines                int64  `json:"lines"`
	Events               int64  `json:"events"`
	Unknown              int64  `json:"unknown"`
	Malformed            int64  `json:"malformed"`
	ClockRegressions     int64  `json:"clock_regressions"`
	SHA256               string `json:"sha256"`
	FirstWall            string `json:"first_wall"`
	LastWall             string `json:"last_wall"`
}

// Read streams at most a 4MiB line into memory. Diagnostics contain counts,
// never unknown phrases or raw input. The caller supplies an immutable prefix.
func Read(ctx context.Context, r io.Reader, p *Profile, node, input string, emit func(Event) error) (Stats, error) {
	var stats Stats
	h := sha256.New()
	sc := bufio.NewScanner(io.TeeReader(r, h))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var current *event.View
	var lastWall time.Time
	run := int64(0)
	for sc.Scan() {
		stats.Lines++
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		m, err := object(raw)
		if err != nil {
			stats.Malformed++
			continue
		}
		msg, module := scalar(m["msg"]), scalar(m["module"])
		if !p.relevant(msg, module) {
			continue
		}
		level := scalar(m["lvl"])
		if level == "" {
			level = scalar(m["level"])
		}
		switch level {
		case "DEBUG-4":
			level = "trace"
		case "DEBUG":
			level = "debug"
		case "INFO":
			level = "info"
		case "WARN":
			level = "warn"
		case "ERROR":
			level = "error"
		}
		ent := p.match(msg, module, level)
		if ent == nil {
			stats.Unknown++
			continue
		}
		wall := scalar(m["t"])
		if wall == "" {
			wall = scalar(m["time"])
		}
		t, err := time.Parse(time.RFC3339Nano, wall)
		if err != nil {
			stats.Malformed++
			continue
		}
		if !lastWall.IsZero() && t.Before(lastWall) {
			stats.ClockRegressions++
		}
		lastWall = t
		if ent.Kind == event.EngineStop {
			current = nil
		}
		// Legacy backend/core each emit start. Only the core line carrying an
		// address starts a new engine session; it resets inferred context.
		if ent.Kind == event.EngineStart && (p.legacy && msg == "WBFT: start" && m["address"] != nil || !p.legacy) {
			run++
			current = nil
		}
		fields := Metadata(m)
		for k, v := range ent.Fields {
			fields[k] = v
		}
		var view *event.View
		inferred := false
		if p.legacy {
			hkey, rkey := "current.sequence", "current.round"
			if ent.Kind == event.RoundEnter {
				hkey, rkey = "next.seq", "next.round"
			}
			if a, b := decimal(scalar(m[hkey])), decimal(scalar(m[rkey])); a != "" && b != "" {
				view = &event.View{Seq: a, Round: b}
			}
			if ent.Kind == event.NewHead {
				if n := decimal(scalar(m["number"])); n != "" {
					view = &event.View{Seq: n}
					if current != nil && current.Seq == n {
						view.Round = current.Round
						inferred = true
					}
				}
			}
		} else if a, b := decimal(scalar(m["h"])), decimal(scalar(m["r"])); a != "" && b != "" {
			view = &event.View{Seq: a, Round: b}
		}
		if view == nil && current != nil && ent.Kind != event.EngineStop && m["address"] != nil {
			v := *current
			view = &v
			inferred = true
		}
		if ent.Kind == event.RoundEnter && view != nil {
			v := *view
			current = &v
		}
		e := Event{Record: event.Record{Kind: ent.Kind, View: view, Src: "log", Fields: fields}, Node: node, Input: input, Run: input + ":" + strconv.FormatInt(run, 10), Wall: t.UTC().Format(time.RFC3339Nano), Level: level, Profile: p.ID, Line: stats.Lines, ViewInferred: inferred}
		if err := emit(e); err != nil {
			return stats, err
		}
		stats.Events++
		if stats.FirstWall == "" {
			stats.FirstWall = e.Wall
		}
		stats.LastWall = e.Wall
	}
	if err := sc.Err(); err != nil {
		return stats, errors.New("log read failed or line exceeds 4MiB")
	}
	stats.SHA256 = hex.EncodeToString(h.Sum(nil))
	return stats, nil
}

// object keeps the first reserved envelope keys. geth can emit a second
// "msg" field when logger context itself names a message; it is not the
// profile phrase. Other duplicate keys are rejected instead of guessed.
func object(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		k, ok := t.(string)
		if !ok {
			return nil, errors.New("invalid key")
		}
		var v json.RawMessage
		if err = d.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := m[k]; dup {
			if k == "msg" {
				continue
			}
			return nil, errors.New("duplicate log key")
		}
		m[k] = v
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing log data")
	}
	return m, nil
}

// Diagnostic describes incomplete normalization without leaking input values.
func (s Stats) Diagnostic() string {
	if s.Unknown == 0 && s.Malformed == 0 {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("unknown consensus phrases: %d; malformed log records: %d", s.Unknown, s.Malformed))
}
