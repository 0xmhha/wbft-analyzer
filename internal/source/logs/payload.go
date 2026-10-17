package logs

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
)

// PayloadWitness is a closed projection of an explicitly logged message.
// It never retains payload or signature bytes, paths or arbitrary log values.
type PayloadWitness struct {
	Status string `json:"status"`
	Phase  string `json:"phase"`
	Code   string `json:"code"`
	Height string `json:"height,omitempty"`
	Round  string `json:"round,omitempty"`
	Signer string `json:"signer,omitempty"`
	Digest string `json:"digest,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// MessagePayload only recognizes the fixed profile's four payload phrases at
// their recorded levels. A missing or inconsistent payload is never inferred
// from a later broadcast, accepted message or absence of errors.
func MessagePayload(raw []byte) *PayloadWitness {
	if len(raw) > 4<<20 {
		return nil
	}
	m, err := object(raw)
	if err != nil {
		return nil
	}
	phrase, level := scalar(m["msg"]), scalar(m["lvl"])
	if level == "" {
		level = scalar(m["level"])
	}
	if level == "DEBUG-4" {
		level = "trace"
	}
	if level == "INFO" {
		level = "info"
	}
	var code codec.Code
	var phase string
	switch {
	case phrase == "WBFT: PRE-PREPARE payload" && level == "trace":
		code, phase = codec.CodePreprepare, "PRE-PREPARE"
	case phrase == "WBFT: PREPARE payload" && level == "trace":
		code, phase = codec.CodePrepare, "PREPARE"
	case phrase == "WBFT: COMMIT payload" && level == "trace":
		code, phase = codec.CodeCommit, "COMMIT"
	case phrase == "WBFT: broadcast ROUND-CHANGE message" && level == "info":
		code, phase = codec.CodeRoundChange, "ROUND-CHANGE"
	default:
		return nil
	}
	out := &PayloadWitness{Status: "invalid", Phase: phase, Code: strconv.FormatUint(uint64(code), 10)}
	value := scalar(m["payload"])
	if value == "" {
		out.Status = "missing"
		return out
	}
	if len(value) > 4<<20 || !strings.HasPrefix(value, "0x") {
		return out
	}
	payload, err := hex.DecodeString(value[2:])
	if err != nil || len(payload) == 0 {
		return out
	}
	msg, err := codec.DecodeMessage(code, payload)
	if err != nil {
		return out
	}
	out.Height, out.Round = msg.View.Sequence.String(), msg.View.Round.String()
	if len(out.Height) > 156 || len(out.Round) > 156 {
		return out
	}
	for key, want := range map[string]string{"msg.code": out.Code, "msg.sequence": out.Height, "msg.round": out.Round} {
		if v, ok := m[key]; ok && scalar(v) != want {
			return out
		}
	}
	signing, err := codec.SigningPayload(msg, false, nil)
	if err != nil {
		return out
	}
	signer, err := ecdsa.RecoverDataSigner(signing, msg.Signature)
	if err != nil {
		return out
	}
	out.Signer = strings.ToLower(signer.Hex())
	if address := scalar(m["address"]); !addressPattern.MatchString(address) || !strings.EqualFold(address, out.Signer) {
		return out
	}
	// An unfilled context address does not override the signer of the bytes.
	if v, ok := m["msg.source"]; ok && !strings.EqualFold(scalar(v), "0x"+strings.Repeat("0", 40)) && !strings.EqualFold(scalar(v), out.Signer) {
		return out
	}
	if msg.Proposal != nil {
		out.Digest = strings.ToLower(codec.BlockHash(msg.Proposal.Header).Hex())
	} else {
		out.Digest = strings.ToLower(msg.Digest.Hex())
	}
	for _, key := range []string{"digest", "proposal.hash", "block.hash"} {
		if v, ok := m[key]; ok && !strings.EqualFold(scalar(v), out.Digest) {
			return out
		}
	}
	sum := sha256.Sum256(payload)
	out.SHA256 = hex.EncodeToString(sum[:])
	out.Status = "decoded"
	return out
}
