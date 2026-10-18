package inputobs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
)

var ErrInput = errors.New("input observations refused")
var address = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commit = regexp.MustCompile(`^[0-9a-f]{40}$`)
var hashValue = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
var identity = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)

type record struct {
	Method           string `json:"method,omitempty"`
	Outcome          string `json:"outcome,omitempty"`
	DurationNS       string `json:"duration_ns,omitempty"`
	ArgumentSHA      string `json:"argument_sha256,omitempty"`
	SubjectHash      string `json:"subject_hash,omitempty"`
	HeadProposer     string `json:"head_proposer,omitempty"`
	Bad              *bool  `json:"is_bad,omitempty"`
	Type             string `json:"type"`
	Sequence         string `json:"sequence"`
	Wall             string `json:"t_wall"`
	Mono             string `json:"t_mono_ns"`
	Format           string `json:"format,omitempty"`
	Node             string `json:"node,omitempty"`
	Run              string `json:"run,omitempty"`
	FrameRun         string `json:"frame_run,omitempty"`
	GenesisSHA       string `json:"genesis_sha256,omitempty"`
	BinarySHA        string `json:"binary_sha256,omitempty"`
	SourceCommit     string `json:"source_commit,omitempty"`
	Ordinal          string `json:"ordinal,omitempty"`
	Instance         string `json:"instance,omitempty"`
	Kind             string `json:"kind,omitempty"`
	Code             string `json:"code,omitempty"`
	Peer             string `json:"peer,omitempty"`
	PeerKnown        *bool  `json:"peer_known,omitempty"`
	PayloadAvailable *bool  `json:"payload_available,omitempty"`
	PayloadSHA       string `json:"payload_sha256,omitempty"`
	Payload          string `json:"payload,omitempty"`
	NilRequest       bool   `json:"nil_request,omitempty"`
	TargetRound      string `json:"target_round,omitempty"`
	View
	Dropped string `json:"dropped,omitempty"`
}

func uintValue(s string) (uint64, bool) {
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil && strconv.FormatUint(n, 10) == s
}
func integer(s string, bits int) bool {
	n, ok := new(big.Int).SetString(s, 10)
	return ok && n.Sign() >= 0 && n.BitLen() <= bits && n.String() == s
}
func validView(v View) bool {
	if v == (View{}) {
		return true
	}
	if !integer(v.Height, 256) || !integer(v.Round, 512) {
		return false
	}
	if v.Proposer != "" && !address.MatchString(v.Proposer) || v.ValsetDigest != "" && !hashValue.MatchString(v.ValsetDigest) {
		return false
	}
	if c := v.Config; c != nil {
		for _, value := range []string{c.RequestTimeoutMS, c.BlockPeriodSeconds, c.Epoch, c.MaxRequestTimeoutSeconds, c.AllowedFutureBlockSeconds, c.ProposerPolicy} {
			if _, ok := uintValue(value); !ok {
				return false
			}
		}
	}
	switch v.State {
	case "Accept request", "Preprepared", "Prepared", "Committed":
		return true
	}
	return false
}

// Read retains only closed metadata and local payload bytes. Missing closure,
// unavailable bytes or peers, overlap and clock regressions remain explicit
// gaps; they are never converted into a complete processing stream.
func Read(ctx context.Context, source io.Reader) (Capture, error) {
	return read(ctx, source, MaxBytes, MaxInputs)
}

func read(ctx context.Context, source io.Reader, maxBytes, maxInputs int) (Capture, error) {
	if err := ctx.Err(); err != nil {
		return Capture{}, err
	}
	if maxBytes < 0 || maxBytes > MaxBytes || maxInputs < 0 || maxInputs > MaxInputs {
		return Capture{}, ErrInput
	}
	out := Capture{Format: Format, Normalizer: Normalizer, Inputs: []Input{}, Unavailable: []string{}}
	limited := &io.LimitedReader{R: source, N: int64(maxBytes) + 1}
	hash := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(limited, hash))
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	missing := map[string]bool{}
	active := map[string]int{}
	instances := map[string]int{}
	var header, closed bool
	var sequence, ordinal, lastMono uint64
	var lastWall time.Time
	var line int64
	var records int
	var answers int
	for scanner.Scan() {
		line++
		if err := ctx.Err(); err != nil {
			return Capture{}, err
		}
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		records++
		if records > maxInputs*10+2 {
			return Capture{}, ErrInput
		}
		var r record
		if closed || jsonmeta.Decode(raw, 4<<20, true, &r) != nil || !recordShape(r) {
			return Capture{}, ErrInput
		}
		n, ok := uintValue(r.Sequence)
		mono, monoOK := uintValue(r.Mono)
		wall, err := time.Parse(time.RFC3339Nano, r.Wall)
		if !ok || !monoOK || err != nil || n == 0 || n <= sequence || !validView(r.View) {
			return Capture{}, ErrInput
		}
		if n != sequence+1 {
			missing["sequence_gap"] = true
		}
		if sequence != 0 && (mono < lastMono || wall.Before(lastWall)) {
			missing["clock_regression"] = true
		}
		sequence, lastMono, lastWall = n, mono, wall
		switch r.Type {
		case "capture_start":
			if header || n != 1 || r.Format != Format || !address.MatchString(r.Node) || !identity.MatchString(r.Run) || !identity.MatchString(r.FrameRun) || !digest.MatchString(r.GenesisSHA) || !digest.MatchString(r.BinarySHA) || !commit.MatchString(r.SourceCommit) {
				return Capture{}, ErrInput
			}
			header = true
			out.Node, out.Run, out.FrameRun, out.GenesisSHA, out.BinarySHA, out.SourceCommit = r.Node, r.Run, r.FrameRun, r.GenesisSHA, r.BinarySHA, r.SourceCommit
		case "begin":
			id, idOK := uintValue(r.Ordinal)
			instance, instanceOK := uintValue(r.Instance)
			if !header || !idOK || id == 0 || id <= ordinal || !instanceOK || instance == 0 || len(out.Inputs) >= maxInputs {
				return Capture{}, ErrInput
			}
			if id != ordinal+1 {
				missing["input_ordinal_gap"] = true
			}
			ordinal = id
			contextGaps(r.View, missing)
			if r.View == (View{}) && r.Kind != "start" {
				missing["input_view_unavailable"] = true
			}
			input := Input{Ordinal: r.Ordinal, Instance: r.Instance, Kind: r.Kind, BeginLine: line, BeginWall: wall.UTC().Format(time.RFC3339Nano), BeginMono: r.Mono, Code: r.Code, Peer: r.Peer, PeerKnown: r.PeerKnown, PayloadAvailable: r.PayloadAvailable, PayloadSHA: r.PayloadSHA, NilRequest: r.NilRequest, TargetRound: r.TargetRound, Before: r.View}
			if err := decodeInput(r, &input, missing); err != nil {
				return Capture{}, err
			}
			if instances[r.Instance] != 0 {
				missing["overlapping_inputs"] = true
			}
			instances[r.Instance]++
			active[r.Ordinal] = len(out.Inputs)
			out.Inputs = append(out.Inputs, input)
		case "answer":
			i, found := active[r.Ordinal]
			if !header || !found || out.Inputs[i].Instance != r.Instance || answers >= maxInputs*8 {
				return Capture{}, ErrInput
			}
			answer, err := decodeAnswer(r, line, missing)
			if err != nil {
				return Capture{}, err
			}
			answers++
			out.Inputs[i].Answers = append(out.Inputs[i].Answers, answer)
		case "end":
			i, found := active[r.Ordinal]
			if !header || !found || out.Inputs[i].Instance != r.Instance {
				return Capture{}, ErrInput
			}
			out.Inputs[i].EndLine, out.Inputs[i].EndWall, out.Inputs[i].After = line, wall.UTC().Format(time.RFC3339Nano), r.View
			out.Inputs[i].EndMono = r.Mono
			contextGaps(r.View, missing)
			if r.View == (View{}) && out.Inputs[i].Kind != "stop" {
				missing["input_view_unavailable"] = true
			}
			instances[r.Instance]--
			delete(active, r.Ordinal)
		case "capture_end":
			dropped, ok := uintValue(r.Dropped)
			if !header || !ok {
				return Capture{}, ErrInput
			}
			if dropped != 0 {
				missing["dropped_records"] = true
			}
			closed = true
		default:
			return Capture{}, ErrInput
		}
	}
	if scanner.Err() != nil || !header || int64(maxBytes)+1-limited.N > int64(maxBytes) {
		return Capture{}, ErrInput
	}
	if err := ctx.Err(); err != nil {
		return Capture{}, err
	}
	if !closed {
		missing["capture_end_unavailable"] = true
	}
	if len(active) != 0 {
		missing["open_inputs"] = true
	}
	for reason := range missing {
		out.Unavailable = append(out.Unavailable, reason)
	}
	sort.Strings(out.Unavailable)
	out.Complete = closed && len(missing) == 0
	out.SHA256, out.Bytes = hex.EncodeToString(hash.Sum(nil)), int64(maxBytes)+1-limited.N
	return out, nil
}

func contextGaps(v View, missing map[string]bool) {
	if v == (View{}) {
		return
	}
	if v.Config == nil {
		missing["configuration_unavailable"] = true
	}
	if v.ValsetDigest == "" {
		missing["validator_context_unavailable"] = true
	}
	if v.Proposer == "" {
		missing["proposer_unavailable"] = true
	}
}

func recordShape(r record) bool {
	kind := r.Type
	r.Type, r.Sequence, r.Wall, r.Mono = "", "", "", ""
	switch kind {
	case "capture_start":
		r.Format, r.Node, r.Run, r.FrameRun, r.GenesisSHA, r.BinarySHA, r.SourceCommit = "", "", "", "", "", "", ""
	case "begin":
		r.Ordinal, r.Instance, r.Kind, r.Code, r.Peer, r.PayloadSHA, r.Payload, r.TargetRound = "", "", "", "", "", "", "", ""
		r.PeerKnown, r.PayloadAvailable, r.NilRequest, r.View = nil, nil, false, View{}
	case "end":
		r.Ordinal, r.Instance, r.View = "", "", View{}
	case "answer":
		r.Ordinal, r.Instance, r.Method, r.Outcome, r.DurationNS = "", "", "", "", ""
		r.ArgumentSHA, r.SubjectHash, r.HeadProposer, r.PayloadSHA, r.Payload = "", "", "", "", ""
		r.Bad, r.PayloadAvailable = nil, nil
	case "capture_end":
		r.Dropped = ""
	default:
		return false
	}
	return r == (record{})
}

func decodeInput(r record, out *Input, missing map[string]bool) error {
	needsPayload := false
	switch r.Kind {
	case "message", "backlog":
		if _, ok := uintValue(r.Code); !ok || r.NilRequest || r.TargetRound != "" {
			return ErrInput
		}
		needsPayload = true
		if r.Kind == "message" && (r.PeerKnown == nil || !*r.PeerKnown) {
			missing["message_peer_unavailable"] = true
		}
		if r.PeerKnown != nil && *r.PeerKnown && !address.MatchString(r.Peer) {
			return ErrInput
		}
		if r.Peer != "" && (r.PeerKnown == nil || !*r.PeerKnown) {
			return ErrInput
		}
	case "request":
		if r.Code != "" || r.Peer != "" || r.PeerKnown != nil || r.TargetRound != "" {
			return ErrInput
		}
		needsPayload = !r.NilRequest
	case "retry_timeout":
		if !integer(r.TargetRound, 512) || r.Code != "" || r.Peer != "" || r.PeerKnown != nil || r.NilRequest {
			return ErrInput
		}
	case "start", "stop", "head", "round_timeout":
		if r.Code != "" || r.Peer != "" || r.PeerKnown != nil || r.NilRequest || r.TargetRound != "" {
			return ErrInput
		}
	default:
		return ErrInput
	}
	if needsPayload {
		if r.PayloadAvailable == nil || !*r.PayloadAvailable {
			if r.Payload != "" || r.PayloadSHA != "" {
				return ErrInput
			}
			missing["input_payload_unavailable"] = true
			return nil
		}
		if !strings.HasPrefix(r.Payload, "0x") || len(r.Payload) > 4<<20 || !digest.MatchString(r.PayloadSHA) {
			return ErrInput
		}
		payload, err := hex.DecodeString(r.Payload[2:])
		if err != nil {
			return ErrInput
		}
		hash := sha256.Sum256(payload)
		if hex.EncodeToString(hash[:]) != r.PayloadSHA {
			return ErrInput
		}
		out.Payload = payload
	} else if r.Payload != "" || r.PayloadSHA != "" || r.PayloadAvailable != nil && *r.PayloadAvailable {
		return ErrInput
	}
	return nil
}
