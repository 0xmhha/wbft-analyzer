package logs

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// RoundHeadWitness projects the explicit head read at a round transition.
// LoggedNumber is the implementation's printed low-width number; the full
// canonical height must be resolved through the exact header hash.
type RoundHeadWitness struct {
	Node           string `json:"node"`
	Hash           string `json:"hash"`
	LoggedNumber   string `json:"logged_number"`
	RequestedRound string `json:"requested_round"`
}

func RoundHead(raw []byte) *RoundHeadWitness {
	if len(raw) > 4<<20 {
		return nil
	}
	m, err := object(raw)
	if err != nil || scalar(m["msg"]) != "WBFT: initialize new round" {
		return nil
	}
	level := scalar(m["lvl"])
	if level == "" {
		level = scalar(m["level"])
	}
	if level != "debug" && level != "DEBUG" {
		return nil
	}
	node, hash := scalar(m["address"]), scalar(m["lastProposal.hash"])
	number, round := decimal(scalar(m["lastProposal.number"])), decimal(scalar(m["target.round"]))
	if !addressPattern.MatchString(node) || !hashPattern.MatchString(hash) || number == "" || round == "" {
		return nil
	}
	// This field is emitted through Uint64, not a full block-number print.
	if _, err := strconv.ParseUint(number, 10, 64); err != nil {
		return nil
	}
	return &RoundHeadWitness{Node: strings.ToLower(node), Hash: strings.ToLower(hash), LoggedNumber: number, RequestedRound: round}
}

// SelectMessagePayload exposes bytes only for an exact, previously validated
// closed payload witness. The caller must bind raw to a pinned log snapshot
// and an original line. Bytes never become part of the witness projection.
func SelectMessagePayload(raw []byte, expected PayloadWitness) ([]byte, uint64, error) {
	failure := errors.New("selected logged message unavailable")
	actual := MessagePayload(raw)
	if actual == nil || actual.Status != "decoded" || *actual != expected {
		return nil, 0, failure
	}
	m, err := object(raw)
	if err != nil {
		return nil, 0, failure
	}
	payload, err := hex.DecodeString(scalar(m["payload"])[2:])
	if err != nil {
		return nil, 0, failure
	}
	code, err := strconv.ParseUint(expected.Code, 10, 64)
	if err != nil {
		return nil, 0, failure
	}
	return payload, code, nil
}
