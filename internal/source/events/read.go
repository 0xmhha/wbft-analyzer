// Package events reads metadata-only WBFT event streams using the pinned schema.
package events

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/event/schema"
)

const Profile = logs.EventProfile
const Normalizer = logs.EventNormalizer

func SchemaHash() string { x := sha256.Sum256(schema.File()); return hex.EncodeToString(x[:]) }

// Read refuses duplicate keys, cross-node identities and repeated/decreasing
// sequence numbers within a run. A new run requires a unique NODE_START at
// sequence zero; native apps append these boundaries across restarts.
// Sequence gaps and monotonic regressions stay diagnostic;
// timestamps are never corrected. Diagnostics do not echo raw records.
func Read(ctx context.Context, r io.Reader, node, input string, emit func(logs.Event) error) (logs.Stats, error) {
	var stats logs.Stats
	check, err := schema.Load()
	if err != nil {
		return stats, err
	}
	h := sha256.New()
	sc := bufio.NewScanner(io.TeeReader(r, h))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var run string
	seenRuns := map[string]bool{}
	var lastSeq, lastMono uint64
	var previous time.Time
	for sc.Scan() {
		stats.Lines++
		if err = ctx.Err(); err != nil {
			return stats, err
		}
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		m, err := object(raw)
		if err != nil || check.Validate(raw) != nil {
			stats.Malformed++
			continue
		}
		var who, engine, wall string
		_ = json.Unmarshal(m["node"], &who)
		_ = json.Unmarshal(m["run"], &engine)
		_ = json.Unmarshal(m["t_wall"], &wall)
		seq, e1 := strconv.ParseUint(string(m["seq"]), 10, 64)
		mono, e2 := strconv.ParseUint(string(m["t_mono_ns"]), 10, 63)
		if who != node || !logs.Identifier(engine) || e1 != nil || e2 != nil {
			return stats, errors.New("event source identity or numeric clock is invalid")
		}
		if run != "" {
			if engine != run {
				var kind event.Kind
				_ = json.Unmarshal(m["kind"], &kind)
				if seq != 0 || kind != event.NodeStart || seenRuns[engine] {
					return stats, errors.New("event source run or sequence order is invalid")
				}
				lastMono = mono
			} else if seq <= lastSeq {
				return stats, errors.New("event source run or sequence order is invalid")
			}
			if engine == run && seq != lastSeq+1 {
				stats.SequenceGaps++
			}
			if mono < lastMono {
				stats.MonotonicRegressions++
			}
		} else if seq != 0 {
			stats.SequenceGaps++
		}
		run = engine
		seenRuns[engine] = true
		lastSeq = seq
		lastMono = mono
		t, err := time.Parse(time.RFC3339Nano, wall)
		if err != nil {
			return stats, errors.New("event wall timestamp is invalid")
		}
		if !previous.IsZero() && t.Before(previous) {
			stats.ClockRegressions++
		}
		previous = t
		var kind event.Kind
		var view *event.View
		_ = json.Unmarshal(m["kind"], &kind)
		if m["view"] != nil {
			_ = json.Unmarshal(m["view"], &view)
		}
		var producer string
		_ = json.Unmarshal(m["src"], &producer)
		if producer == event.AppSrc && event.IsNodeKind(kind) {
			stats.Malformed++
			continue
		}
		fields := Metadata(m)
		if view == nil && kind == event.NewHead {
			number, _ := fields["number"].(string)
			round, _ := fields["round"].(string)
			if number != "" && round != "" {
				view = &event.View{Seq: number, Round: round}
			}
		}
		monoText := strconv.FormatUint(mono, 10)
		e := logs.Event{Record: event.Record{Kind: kind, View: view, Src: "event", Fields: fields}, Mono: &monoText, Node: node, Input: input, Run: engine, Wall: t.UTC().Format(time.RFC3339Nano), Line: stats.Lines, Level: "event", Profile: Profile}
		if err = emit(e); err != nil {
			return stats, err
		}
		stats.Events++
		if stats.FirstWall == "" {
			stats.FirstWall = e.Wall
		}
		stats.LastWall = e.Wall
	}
	if sc.Err() != nil {
		return stats, errors.New("event read failed or line exceeds 4MiB")
	}
	stats.SHA256 = hex.EncodeToString(h.Sum(nil))
	return stats, nil
}
func object(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, errors.New("invalid event object")
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return nil, err
		}
		k, ok := t.(string)
		if !ok || m[k] != nil {
			return nil, errors.New("duplicate event key")
		}
		var b json.RawMessage
		if err = d.Decode(&b); err != nil {
			return nil, err
		}
		m[k] = b
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing event data")
	}
	return m, nil
}

// Metadata is reapplied at persistence, independently of schema validation.
// Nested values, payload, data, arbitrary error text and unknown fields are absent.
func Metadata(m map[string]json.RawMessage) map[string]any {
	out := logs.Metadata(m)
	var kind event.Kind
	_ = json.Unmarshal(m["kind"], &kind)
	if kind == event.BuildHandover || kind == event.BuildStarted || kind == event.BuildFinished {
		var id string
		if json.Unmarshal(m["build_id"], &id) == nil && len(id) <= 26 && strings.HasPrefix(id, "build-") {
			n, err := strconv.ParseUint(strings.TrimPrefix(id, "build-"), 10, 64)
			if err == nil && n > 0 && id == "build-"+strconv.FormatUint(n, 10) {
				out["build_id"] = id
			}
		}
		var status string
		if kind == event.BuildFinished && json.Unmarshal(m["status"], &status) == nil {
			switch status {
			case "submitted", "replaced", "height_left", "stopped", "unavailable", "head_changed", "failed":
				out["status"] = status
			}
		}
	}
	if kind == event.StateChange {
		for _, k := range []string{"from", "to"} {
			var s string
			if json.Unmarshal(m[k], &s) == nil && (s == "AcceptRequest" || s == "Preprepared" || s == "Prepared" || s == "Committed") {
				out[k] = s
			}
		}
	}
	for _, k := range []string{"seq", "step", "count", "row", "gen", "engine_run", "deadline_mono_ns", "duration_ms", "requested_round", "wait_ms", "wait_ns"} {
		raw := m[k]
		if len(raw) == 0 {
			continue
		}
		var text string
		if json.Unmarshal(raw, &text) != nil {
			text = string(raw)
		}
		v, err := strconv.ParseUint(text, 10, 64)
		if err == nil {
			out[k] = strconv.FormatUint(v, 10)
		}
	}
	// Flatten only the schema-defined sign floor, including the already-flat
	// form when metadata is reapplied at persistence. No arbitrary nested map
	// crosses this boundary.
	if kind == event.NodeStart {
		if bytes.Equal(bytes.TrimSpace(m["sign_floor"]), []byte("null")) {
			out["sign_floor_state"] = "none"
		} else {
			var state string
			if json.Unmarshal(m["sign_floor_state"], &state) == nil && state == "none" {
				out["sign_floor_state"] = state
			}
		}
		var validator bool
		if json.Unmarshal(m["validator"], &validator) == nil {
			out["validator"] = validator
		}
		var floor struct {
			Height string `json:"height"`
			Status string `json:"status"`
		}
		_ = json.Unmarshal(m["sign_floor"], &floor)
		if floor.Height == "" {
			_ = json.Unmarshal(m["sign_floor_height"], &floor.Height)
			_ = json.Unmarshal(m["sign_floor_status"], &floor.Status)
		}
		if len(floor.Height) > 156 {
			floor.Height = ""
		}
		if n, ok := new(big.Int).SetString(floor.Height, 10); len(floor.Height) <= 156 && ok && n.Sign() >= 0 && n.String() == floor.Height && (floor.Status == "set" || floor.Status == "kept" || floor.Status == "cleared") {
			out["sign_floor_height"], out["sign_floor_status"] = floor.Height, floor.Status
		}
	}
	if kind == event.EngineStart {
		// Preserve policy separately from the observed result. False replayed
		// with an empty WAL never proves that replay was disabled.
		var replay map[string]json.RawMessage
		_ = json.Unmarshal(m["replay"], &replay)
		for original, flat := range map[string]string{"enabled": "wal_replay_enabled", "available": "wal_available", "replayed": "wal_replayed"} {
			raw := replay[original]
			if len(raw) == 0 {
				raw = m[flat]
			}
			var value bool
			if bytes.Equal(bytes.TrimSpace(raw), []byte("true")) || bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
				if json.Unmarshal(raw, &value) == nil {
					out[flat] = value
				}
			}
		}
		raw := replay["records"]
		if len(raw) == 0 {
			raw = m["wal_replay_records"]
		}
		var records string
		if json.Unmarshal(raw, &records) != nil {
			records = string(raw)
		}
		if n, err := strconv.ParseUint(records, 10, 64); err == nil {
			out["wal_replay_records"] = strconv.FormatUint(n, 10)
		}
		raw = replay["stopped"]
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			out["wal_replay_status"] = "complete"
		} else if len(raw) > 0 {
			var text string
			if json.Unmarshal(raw, &text) == nil && text != "" {
				out["wal_replay_status"] = "stopped"
			}
		}
		if out["wal_replay_status"] == nil {
			var status string
			if json.Unmarshal(m["wal_replay_status"], &status) == nil && (status == "complete" || status == "stopped") {
				out["wal_replay_status"] = status
			}
		}
	}
	if kind == event.Health {
		// HEALTH and QUORUM use different schema-defined values of what.
		// Keep operator conditions only for native HEALTH records.
		var what string
		_ = json.Unmarshal(m["what"], &what)
		delete(out, "what")
		switch what {
		case "head_mismatch", "peer_inbound_overflow", "peer_inbound_disconnect", "privval_refusal", "sign_floor_skip",
			"snapshot_missing_at_preprepare", "snapshot_missing_at_head", "consensus_halted", "disconnect":
			out["what"] = what
		}
		var height string
		_ = json.Unmarshal(m["h"], &height)
		if len(height) > 156 {
			height = ""
		}
		if n, ok := new(big.Int).SetString(height, 10); ok && n.Sign() >= 0 && n.String() == height && len(height) <= 156 {
			out["h"] = height
		}
	}
	var round string
	if json.Unmarshal(m["requested_round"], &round) == nil && len(round) <= 156 {
		if n, ok := new(big.Int).SetString(round, 10); ok && n.Sign() >= 0 && n.String() == round {
			out["requested_round"] = round
		}
	}
	for _, k := range []string{"is_proposer", "stale", "ok"} {
		var b bool
		if json.Unmarshal(m[k], &b) == nil {
			out[k] = b
		}
	}
	var op string
	if json.Unmarshal(m["op"], &op) == nil && (op == "push" || op == "pop" || op == "drop") {
		out["op"] = op
	}
	return out
}
