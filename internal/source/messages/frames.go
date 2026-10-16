package messages

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type frameRecord struct {
	Scheduler      json.RawMessage `json:"scheduler_trace"`
	Timer          json.RawMessage `json:"timer_operation"`
	EntryMono      *string         `json:"entry_t_mono_ns"`
	EntryWall      string          `json:"entry_t_wall"`
	ClockSource    string          `json:"clock_source"`
	OwnMessageOf   *uint64         `json:"own_message_of"`
	InputOf        *uint64         `json:"input_of"`
	InputKind      string          `json:"input_kind"`
	EngineRun      *uint64         `json:"engine_run"`
	Step           *uint64         `json:"step"`
	JournalSegment *uint64         `json:"journal_segment"`
	JournalOffset  *int64          `json:"journal_offset"`

	V             int             `json:"v"`
	Type          string          `json:"type"`
	Node          string          `json:"node"`
	Run           string          `json:"run"`
	Seq           *uint64         `json:"seq"`
	Wall          string          `json:"t_wall"`
	Mono          *int64          `json:"t_mono_ns"`
	Dir           string          `json:"dir"`
	Peer          *string         `json:"peer"`
	Code          string          `json:"code"`
	WireCode      *uint64         `json:"wire_code"`
	Size          *uint64         `json:"size"`
	Payload       string          `json:"payload_sha256"`
	PayloadSource json.RawMessage `json:"payload_source"`
	Key           string          `json:"dedup_key"`
	Outcome       string          `json:"outcome"`
	WriteError    string          `json:"write_error"`
	WriteResult   json.RawMessage `json:"write_result"`
	IO            json.RawMessage `json:"io"`
	Cause         string          `json:"cause"`
	RelayOf       *uint64         `json:"relay_of"`
	Of            *uint64         `json:"of"`
	Engine        string          `json:"engine"`
	Check         string          `json:"check"`
	Via           string          `json:"via"`
	Event         string          `json:"event"`
	Count         *uint64         `json:"count"`
	Dedup         *struct {
		Known      *bool `json:"known_hit"`
		PeerRecent *bool `json:"peer_recent_hit"`
	} `json:"dedup"`
}

func readFramesRaw(ctx context.Context, p Prepared, emit func(Record) error) (s Stats, err error) {
	s.ClockDiagnostics = "unavailable_export_order"
	sawOwn := false
	sawScheduler := false
	sawCache := false
	root, e := os.OpenRoot(p.Input.Path)
	if e != nil {
		return s, errors.New("cannot open frame input")
	}
	defer root.Close()
	// A bounded bitset would lose sparse original seq values. Retain exact
	// uniqueness for up to one million records per input, then refuse explicitly.
	seen := map[string]bool{}
	for _, f := range p.Summary.Files {
		if !frameName.MatchString(f.Name) {
			continue
		}
		fd, e := root.Open(f.Name)
		if e != nil {
			return s, errors.New("cannot read frame records")
		}
		e = func() error {
			defer fd.Close()
			digest := sha256.New()
			sc := bufio.NewScanner(io.TeeReader(fd, digest))
			sc.Buffer(make([]byte, 64<<10), 4<<20)
			for line := int64(1); sc.Scan(); line++ {
				if e := ctx.Err(); e != nil {
					return e
				}
				b := sc.Bytes()
				if len(bytes.TrimSpace(b)) == 0 {
					continue
				}
				// Detect the new evidence shape even when its fields are malformed.
				var fields map[string]json.RawMessage
				if json.Unmarshal(b, &fields) != nil {
					return errors.New("invalid frame JSON fields")
				}
				for _, name := range []string{"cache_trace", "cache_instance", "cache_operation", "cache_decision", "send_attempt"} {
					if fields[name] != nil {
						sawCache = true
					}
				}
				var kind string
				_ = json.Unmarshal(fields["type"], &kind)
				if kind == "cache_trace" || kind == "cache_instance" || kind == "cache_operation" {
					sawCache = true
				}
				if kind == "scheduler_trace" || kind == "scheduler_step" || kind == "timer_operation" || fields["scheduler_trace"] != nil || fields["timer_operation"] != nil {
					sawScheduler = true
				}
				if (fields["scheduler_trace"] != nil && kind != "scheduler_trace") || (fields["timer_operation"] != nil && kind != "timer_operation") {
					return errSchedulerFrameSource
				}
				for _, name := range []string{"entry_t_mono_ns", "entry_t_wall"} {
					if v, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
						return errSchedulerFrameSource
					}
				}
				_, ownRef := fields["own_message_of"]
				_, inputRef := fields["input_of"]
				if kind == "own_input" || ownRef || inputRef {
					sawOwn = true
				}
				if !uniqueObject(b) {
					return errors.New("invalid or duplicate frame JSON fields")
				}
				for _, name := range []string{"own_message_of", "input_of"} {
					if value, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
						return errors.New("null own-input reference")
					}
				}
				var x frameRecord

				if json.Unmarshal(b, &x) != nil || x.V != 1 || !addressPattern.MatchString(x.Node) || strings.ToLower(x.Node) != p.Summary.Node || x.Run == "" || len(x.Run) > 128 || x.Seq == nil || x.Mono == nil {
					return errors.New("invalid frame identity or sequence")
				}
				write, e := frameWriteResult(x)
				if e != nil {
					return e
				}
				payloadSource, e := framePayloadSource(x, write)
				if e != nil {
					return e
				}
				span, e := frameIOInterval(x, write)
				if e != nil {
					return e
				}
				seq := x.Run + ":" + number(*x.Seq)
				if seen[seq] {
					return errors.New("duplicate frame sequence")
				}
				if len(seen) >= 1000000 {
					return errors.New("frame input exceeds one million records")
				}
				seen[seq] = true
				wall, e := time.Parse(time.RFC3339Nano, x.Wall)
				if e != nil {
					return errors.New("invalid frame wall time")
				}
				r := Record{ClockSource: "inherited", Input: p.Input.ID, File: f.Name, Ordinal: line, Seq: number(*x.Seq), Node: p.Summary.Node, Run: x.Run, Type: x.Type, Wall: wall.UTC().Format(time.RFC3339Nano), Mono: signed(*x.Mono)}
				if x.Peer != nil && *x.Peer != "" {
					if !addressPattern.MatchString(*x.Peer) {
						return errors.New("invalid frame peer")
					}
					r.Peer = strings.ToLower(*x.Peer)
				}
				if x.Key != "" && !hashPattern.MatchString(x.Key) {
					return errors.New("invalid frame key")
				}
				if (x.Type == "own_input" || x.OwnMessageOf != nil || x.InputOf != nil) && (!hashPattern.MatchString(x.Key) || x.Key == "0x"+strings.Repeat("0", 64)) {
					return errors.New("own input requires explicit message key")
				}
				r.Key = strings.ToLower(x.Key)
				if r.Key == "0x"+strings.Repeat("0", 64) {
					r.Key = ""
				}

				if x.OwnMessageOf != nil {
					r.OwnMessageOf = number(*x.OwnMessageOf)
				}
				if x.InputOf != nil {
					r.InputOf = number(*x.InputOf)
				}
				if x.EngineRun != nil {
					r.EngineRun = number(*x.EngineRun)
				}
				if x.Step != nil {
					r.Step = number(*x.Step)
				}
				if x.Type == "own_input" {
					r.InputKind = choice(x.InputKind, "message")
					r.Via = choice(x.Via, "internal")
					if x.JournalSegment != nil && x.JournalOffset != nil {
						r.Journal = &JournalPosition{number(*x.JournalSegment), strconv.FormatInt(*x.JournalOffset, 10)}
					}
				}
				r.Cause = choice(x.Cause, "broadcast", "gossip", "relay", "retry", "reconnect", "replay", "direct")
				switch x.Type {
				case "frame", "own_input":
					r.PayloadSource = payloadSource
					r.IO = span
					r.ClockSource = "recorded"
					if x.Type == "frame" && x.Dir != "in" && x.Dir != "out" || x.Size == nil || x.Type == "own_input" && x.Dir != "" {
						return errors.New("invalid frame direction or size")
					}
					r.Dir = x.Dir
					r.Engine = choice(x.Engine, "running", "stopped", "syncing")
					size := number(*x.Size)
					r.Size = &size
					if r.Peer == "" {
						r.PeerStatus = "unknown"
					} else {
						r.PeerStatus = "recorded"
					}
					code, e := strconv.ParseUint(strings.TrimPrefix(x.Code, "0x"), 16, 64)
					if e != nil {
						return errors.New("invalid frame code")
					}
					if x.WireCode != nil {
						v := number(*x.WireCode)
						r.WireCode = &v
					}
					if x.Dir == "out" {
						r.Write = write
					}
					r.Outcome = choice(x.Outcome, "PENDING", "ACCEPT", "IGNORE", "DROP_SILENT", "DISCONNECT")
					if x.Dedup != nil {
						r.KnownHit = x.Dedup.Known
						r.PeerRecentHit = x.Dedup.PeerRecent
					}
					if x.RelayOf != nil {
						r.RelayOf = number(*x.RelayOf)
					}
					var payload []byte
					if x.Payload != "" {
						r.PayloadSHA256 = x.Payload
						if !shaPattern.MatchString(x.Payload) {
							return errors.New("invalid payload checksum")
						}
						pf, e := root.Open("payloads/" + x.Payload[:2] + "/" + x.Payload)
						if e != nil {
							r.Decode = "missing_payload"
						} else {
							payload, e = io.ReadAll(io.LimitReader(pf, (16<<20)+1))
							pf.Close()
							if e != nil {
								return errors.New("cannot read frame payload")
							}
							if len(payload) > 16<<20 {
								r.Decode = "oversized"
								payload = nil
							} else {
								sum := sha256.Sum256(payload)
								if hex.EncodeToString(sum[:]) != x.Payload {
									return errors.New("frame payload checksum mismatch")
								}
								if uint64(len(payload)) != *x.Size {
									return errors.New("frame payload size mismatch")
								}
							}
						}
					}
					if r.Decode == "" {
						decode(&r, code, payload, false)
					} else {
						r.Phase = phase(code)
					}
				case "cache_trace", "cache_instance", "cache_operation":
				case "scheduler_trace", "scheduler_step", "timer_operation":
					if e = projectSchedulerFrame(&r, x, fields); e != nil {
						return e
					}
				case "outcome":
					if x.Code != "" {
						code, e := strconv.ParseUint(strings.TrimPrefix(x.Code, "0x"), 16, 64)
						if e != nil {
							return errors.New("invalid outcome code")
						}
						r.Phase = phase(code)
					}
					if x.Of != nil {
						r.Of = number(*x.Of)
					}
					r.Outcome = choice(x.Outcome, "ACCEPT", "IGNORE", "DROP_SILENT", "DISCONNECT")
					r.Check = choice(x.Check, "PROCESS", "FUTURE", "OLD", "INVALID", "EXTRA_SEAL", "TOO_FAR", "prefilter")
					r.Via = choice(x.Via, "direct", "backlog", "future_block", "self")
				case "conn":
					r.Event = choice(x.Event, "handshake", "hello", "eth_registered", "istanbul_attached", "closed")
				case "send_suppressed":
				case "dropped":
					r.Type = "gap"
					if x.Count == nil {
						return errors.New("dropped frame count missing")
					}
					r.Dropped = number(*x.Count)
				default:
					return errors.New("unknown frame record type")
				}
				if x.Type == "own_input" && (x.EntryMono != nil || x.EntryWall != "") {
					if e = projectSchedulerEntry(&r, x); e != nil {
						return e
					}
				}
				if e = projectCacheFrame(&r, x, fields); e != nil {
					return e
				}
				if e = emit(r); e != nil {
					return e
				}
				observe(&s, r)
			}
			if sc.Err() != nil {
				return errors.New("frame line damaged or oversized")
			}
			if f.SHA256 != "" && hex.EncodeToString(digest.Sum(nil)) != f.SHA256 {
				return errors.New("frame file changed during read")
			}
			return nil
		}()
		if e != nil {
			if sawCache {
				return s, errors.Join(errCacheFrameSource, e)
			}
			if sawScheduler {
				return s, errors.Join(errSchedulerFrameSource, e)
			}
			if sawOwn {
				return s, errors.Join(errOwnFrameProvenance, e)
			}
			return s, e
		}
	}
	return s, nil
}

func uniqueObject(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		t, e = d.Token()
		if e != nil {
			return false
		}
		k, ok := t.(string)
		if !ok || seen[k] {
			return false
		}
		seen[k] = true
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return false
		}
	}
	t, e = d.Token()
	return e == nil && t == json.Delim('}') && d.Decode(new(any)) == io.EOF
}

// frameWriteResult accepts only an explicit transport result as success.
// Old error absence stays unknown; contradictory or malformed declarations
// must not enter retained metadata as a successful write.
func frameWriteResult(x frameRecord) (string, error) {
	if len(x.WriteResult) > 0 {
		if x.Type != "frame" || x.Dir != "out" {
			return "", errors.New("write result outside outgoing frame")
		}
		var declared string
		if json.Unmarshal(x.WriteResult, &declared) != nil || choice(declared, "ok", "error", "not_attached") == "" {
			return "", errors.New("invalid explicit frame write result")
		}
		if x.WriteError != "" && (declared == "ok" || declared == "not_attached" && x.WriteError != "not_attached" || declared == "error" && x.WriteError == "not_attached") {
			return "", errors.New("contradictory frame write result")
		}
		return declared, nil
	}
	if x.Type != "frame" || x.Dir != "out" {
		return "", nil
	}
	if x.WriteError == "" {
		return "no_error_recorded", nil
	}
	if x.WriteError == "not_attached" {
		return "not_attached", nil
	}
	return "error", nil
}

// framePayloadSource describes which bytes were observed. A snapshot of the
// provided reader on a failed write proves neither consumption nor delivery.
func framePayloadSource(x frameRecord, write string) (string, error) {
	if len(x.PayloadSource) == 0 {
		return "", nil
	}
	var source string
	if json.Unmarshal(x.PayloadSource, &source) != nil || x.Type != "frame" || !shaPattern.MatchString(x.Payload) || x.Size == nil {
		return "", errors.New("invalid frame payload source")
	}
	switch source {
	case "consumed":
		return source, nil
	case "provided_reader_snapshot":
		if x.Dir == "out" && write == "error" {
			return source, nil
		}
	}
	return "", errors.New("invalid frame payload source")
}
