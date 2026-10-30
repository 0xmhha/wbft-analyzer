package scenario

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/p2p/transport"
)

// RecordedMessageSelection names one incoming recorded copy and explicitly
// chooses an eligible occurrence in the fitted model. Native and simulated
// payload hashes differ because the model uses its own test keys.
type RecordedMessageSelection struct {
	Input      string `json:"input"`
	File       string `json:"file"`
	Ordinal    int64  `json:"ordinal,string"`
	Occurrence uint64 `json:"model_occurrence,string"`
}

func (v *RecordedMessageSelection) UnmarshalJSON(raw []byte) error {
	type wire RecordedMessageSelection
	var decoded wire
	if err := decodeTimingObject(raw, &decoded, map[string]bool{"input": true, "file": true, "ordinal": true, "model_occurrence": true}, "input", "file", "ordinal", "model_occurrence"); err != nil {
		return err
	}
	if !validMessageSelection(RecordedMessageSelection(decoded)) {
		return errNetworkChange
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return errNetworkChange
	}
	for name, want := range map[string]string{"ordinal": strconv.FormatInt(decoded.Ordinal, 10), "model_occurrence": strconv.FormatUint(decoded.Occurrence, 10)} {
		var value string
		if json.Unmarshal(fields[name], &value) != nil || value != want {
			return errNetworkChange
		}
	}
	*v = RecordedMessageSelection(decoded)
	return nil
}

func validMessageSelection(v RecordedMessageSelection) bool {
	return logs.Identifier(v.Input) && v.File != "" && len(v.File) <= 160 && !strings.ContainsAny(v.File, "/\\") && v.File != "." && v.File != ".." && v.Ordinal > 0 && v.Occurrence > 0
}

func (c NetworkChange) IsMessageChange() bool {
	return c.Kind == "drop_message" || c.Kind == "swap_messages"
}

func normalizeMessageChange(c NetworkChange) (NetworkChange, error) {
	want := 1
	if c.Kind == "swap_messages" {
		want = 2
	}
	if c.FromNS != 0 || c.Node != nil || c.Edges != nil || c.DelayNS != nil || c.Scale != nil || c.Lifecycle != nil || c.SchedulePolicy != "" || c.Timing != nil || len(c.Messages) != want {
		return NetworkChange{}, errNetworkChange
	}
	for _, ref := range c.Messages {
		if !validMessageSelection(ref) {
			return NetworkChange{}, errNetworkChange
		}
	}
	if want == 2 && c.Messages[0].Input == c.Messages[1].Input && c.Messages[0].File == c.Messages[1].File && c.Messages[0].Ordinal == c.Messages[1].Ordinal {
		return NetworkChange{}, errNetworkChange
	}
	c.Messages = append([]RecordedMessageSelection(nil), c.Messages...)
	return c, nil
}

type ModelMessageSelector struct {
	Peer       int    `json:"peer_node"`
	Receiver   int    `json:"receiver_node"`
	Signer     int    `json:"signer_node"`
	Code       uint64 `json:"code,string"`
	Height     string `json:"height"`
	Round      string `json:"round"`
	Occurrence uint64 `json:"occurrence,string"`
}

type RecordedMessageBinding struct {
	Selection RecordedMessageSelection `json:"selection"`
	Native    RecordedMessageEvidence  `json:"recorded_message"`
	Effective ModelMessageSelector     `json:"effective_selector"`
}

type RecordedMessageEvidence struct {
	Input         string `json:"input"`
	InputSHA256   string `json:"input_sha256"`
	File          string `json:"file"`
	Ordinal       int64  `json:"ordinal,string"`
	Run           string `json:"receiver_run"`
	Node          string `json:"receiver"`
	Peer          string `json:"peer"`
	Signer        string `json:"signer"`
	Height        string `json:"height"`
	Round         string `json:"round"`
	Phase         string `json:"phase"`
	PayloadSHA256 string `json:"payload_sha256"`
}

type MessageEffect struct {
	ExecutionSHA256 string                   `json:"execution_sha256"`
	Source          string                   `json:"source"`
	Scope           string                   `json:"scope"`
	Selections      []RecordedMessageBinding `json:"selections"`
}

var ErrRecordedDomainModelUnavailable = errors.New("recorded chain domain requires a domain-aware message model")

// BindRecordedMessage checks the entire signed payload with the official core,
// separately from the stored top-level signature projection. Relay identity
// and signer rank are mapped independently to the model's test validators.
func BindRecordedMessage(ref RecordedMessageSelection, row messages.Record, payload []byte, code uint64, recorded []string) (RecordedMessageBinding, error) {
	if row.SigningProfile != nil {
		return RecordedMessageBinding{}, ErrRecordedDomainModelUnavailable
	}
	fail := func() (RecordedMessageBinding, error) { return RecordedMessageBinding{}, errNetworkChange }
	if !validMessageSelection(ref) || ref.Input != row.Input || ref.File != row.File || ref.Ordinal != row.Ordinal || row.Type != "frame" || row.Dir != "in" || row.PeerStatus != "recorded" || row.Decode != "decoded" || row.Signature != "recovered" || code < 0x12 || code > 0x15 {
		return fail()
	}
	_, actualCode, action, _ := transport.DecodeFrame(code, payload)
	if action != transport.FrameDeliver || actualCode != code {
		return fail()
	}
	hash := sha256.Sum256(payload)
	if hex.EncodeToString(hash[:]) != row.PayloadSHA256 {
		return fail()
	}
	phase := map[uint64]string{0x12: "PRE-PREPARE", 0x13: "PREPARE", 0x14: "COMMIT", 0x15: "ROUND-CHANGE"}[code]
	if row.Phase != phase {
		return fail()
	}
	verified, err := consensus.Recover(codec.Code(code), payload, nil)
	if err != nil || !strings.EqualFold(verified.Source.Hex(), row.Signer) || verified.Msg.View.Sequence.String() != row.Height || verified.Msg.View.Round.String() != row.Round {
		return fail()
	}
	index := func(address string) int {
		found := -1
		for i, value := range recorded {
			if strings.EqualFold(value, address) {
				if found >= 0 {
					return -1
				}
				found = i
			}
		}
		return found
	}
	peer, receiver, signer := index(row.Peer), index(row.Node), index(row.Signer)
	if peer < 0 || receiver < 0 || signer < 0 || peer == receiver {
		return fail()
	}
	native := RecordedMessageProjection(row, "")
	return RecordedMessageBinding{Selection: ref, Native: native, Effective: ModelMessageSelector{Peer: peer, Receiver: receiver, Signer: signer, Code: code, Height: row.Height, Round: row.Round, Occurrence: ref.Occurrence}}, nil
}

// RecordedMessageProjection exposes exact coordinates without payload bytes.
// This projection alone does not establish frame or justification validity.
func RecordedMessageProjection(row messages.Record, inputSHA string) RecordedMessageEvidence {
	return RecordedMessageEvidence{Input: row.Input, InputSHA256: inputSHA, File: row.File, Ordinal: row.Ordinal, Run: row.Run, Node: row.Node, Peer: row.Peer, Signer: row.Signer, Height: row.Height, Round: row.Round, Phase: row.Phase, PayloadSHA256: row.PayloadSHA256}
}

func (m ModelMessageSelector) selector(sc sim.Scenario) (sim.MessageSelector, error) {
	n := len(sc.Validators)
	if m.Peer < 0 || m.Receiver < 0 || m.Signer < 0 || m.Peer >= n || m.Receiver >= n || m.Signer >= n || m.Peer == m.Receiver || m.Code < 0x12 || m.Code > 0x15 || m.Occurrence == 0 {
		return sim.MessageSelector{}, errNetworkChange
	}
	for i, text := range []string{m.Height, m.Round} {
		value, ok := new(big.Int).SetString(text, 10)
		if !ok || value.Sign() < 0 || i == 0 && value.Sign() == 0 || value.String() != text || len(text) > 156 {
			return sim.MessageSelector{}, errNetworkChange
		}
	}
	return sim.MessageSelector{Peer: sc.Validators[m.Peer].Address(), Receiver: sc.Validators[m.Receiver].Address(), Signer: sc.Validators[m.Signer].Address(), Code: codec.Code(m.Code), Sequence: m.Height, Round: m.Round, Occurrence: m.Occurrence}, nil
}

// ApplyMessageChange is usable only after binding exact immutable source rows.
// It changes transport delivery only; the official runner still chooses core
// inputs and may reject a delivery or never enter it into a handler.
func ApplyMessageChange(sc sim.Scenario, change NetworkChange, bindings []RecordedMessageBinding) (sim.Scenario, *MessageEffect, string, error) {
	if !change.IsMessageChange() || change.ValidateFor(len(sc.Validators), sc.Until.Duration) != nil || len(bindings) != len(change.Messages) || len(sc.MessageChanges) != 0 {
		return sc, nil, "", errNetworkChange
	}
	selectors := make([]sim.MessageSelector, len(bindings))
	for i, b := range bindings {
		if b.Selection != change.Messages[i] || b.Native.Input != b.Selection.Input || b.Native.File != b.Selection.File || b.Native.Ordinal != b.Selection.Ordinal || b.Effective.Occurrence != b.Selection.Occurrence || b.Effective.Height != b.Native.Height || b.Effective.Round != b.Native.Round {
			return sc, nil, "", errNetworkChange
		}
		var err error
		selectors[i], err = b.Effective.selector(sc)
		if err != nil {
			return sc, nil, "", err
		}
	}
	control := sim.MessageDeliveryChange{Kind: sim.MessageDrop, First: selectors[0]}
	if len(selectors) == 2 {
		if selectors[0].Receiver != selectors[1].Receiver || selectors[0] == selectors[1] {
			return sc, nil, "", errNetworkChange
		}
		control.Kind, control.Second = sim.MessageSwap, &selectors[1]
	}
	sc.MessageChanges = []sim.MessageDeliveryChange{control}
	executionHash, err := ExecutionHash(sc)
	if err != nil {
		return sc, nil, "", err
	}
	_, hash, err := change.Canonical()
	if err != nil {
		return sc, nil, "", err
	}
	effect := &MessageEffect{ExecutionSHA256: executionHash, Source: "verified_recorded_message_to_test_validator_rank/1", Scope: "one_eligible_transport_copy_per_selection_across_receiver_incarnations", Selections: append([]RecordedMessageBinding(nil), bindings...)}
	return sc, effect, hash, nil
}
