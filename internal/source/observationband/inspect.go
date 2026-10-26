// Package observationband checks the arithmetic of an untrusted node report.
// It does not authenticate headers, state roots, membership or signatures.
package observationband

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"

	wbftrpc "github.com/0xmhha/wbft/rpc"
)

const MaxReportBytes = 64 << 10

var ErrReport = errors.New("invalid or unsupported observation-band report")

type Arithmetic struct {
	HistoryStatus   string  `json:"history_status" enum:"NO_HISTORY,INSUFFICIENT_HISTORY,SUFFICIENT_HISTORY"`
	ObservedBand    *string `json:"observed_band"`
	MatchesReported bool    `json:"matches_reported"`
}

type Inspection struct {
	Schema       string                        `json:"schema"`
	SourceSHA256 string                        `json:"source_sha256"`
	SourceScope  string                        `json:"source_scope" enum:"node_reported"`
	Report       wbftrpc.ObservationBandResult `json:"report"`
	Arithmetic   *Arithmetic                   `json:"arithmetic"`
}

func closed(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrReport
	}
	return nil
}
func integer(s string, positive bool) (*big.Int, error) {
	if len(s) == 0 || len(s) > 256 || len(s) > 1 && s[0] == '0' {
		return nil, ErrReport
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, ErrReport
		}
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || positive && n.Sign() == 0 {
		return nil, ErrReport
	}
	return n, nil
}
func hexValue(s string, n int) bool {
	if len(s) != 2+2*n || !strings.HasPrefix(s, "0x") {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}
func sameBand(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

// Inspect accepts a result object or its JSON-RPC 2.0 response envelope.
// It retains a raw-file digest but never upgrades a node's claim to verified
// chain evidence. A mismatch is an arithmetic discrepancy, not a verdict on
// consensus validity, signing intent, eligibility or rewards.
func Inspect(raw []byte) (*Inspection, error) {
	if len(raw) == 0 || len(raw) > MaxReportBytes {
		return nil, ErrReport
	}
	payload := raw
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil || keys == nil {
		return nil, ErrReport
	}
	if _, ok := keys["jsonrpc"]; ok {
		var envelope struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   json.RawMessage `json:"error"`
		}
		if closed(raw, &envelope) != nil || envelope.JSONRPC != "2.0" || len(envelope.Result) == 0 || len(envelope.Error) > 0 && !bytes.Equal(bytes.TrimSpace(envelope.Error), []byte("null")) {
			return nil, ErrReport
		}
		payload = envelope.Result
	}
	var report wbftrpc.ObservationBandResult
	if closed(payload, &report) != nil || report.Schema != "wbft-observation-band-rpc/1" || len(report.Reason) > 512 || len(report.CoreVersion) > 256 {
		return nil, ErrReport
	}
	sum := sha256.Sum256(raw)
	out := &Inspection{Schema: "wbft-analyzer-observation-band/1", SourceSHA256: hex.EncodeToString(sum[:]), SourceScope: "node_reported", Report: report}
	switch report.Status {
	case "DISABLED", "BEFORE_ACTIVATION", "UNAVAILABLE", "UNSUPPORTED":
		if report.Diagnostic != nil || report.VerificationScope != "" {
			return nil, ErrReport
		}
		return out, nil
	case "AVAILABLE":
	default:
		return nil, ErrReport
	}
	d := report.Diagnostic
	if d == nil || report.VerificationScope != "node_adopted_observation_state" || !hexValue(report.GenesisHash, 32) || d.Schema != "wbft-observation-band/1" || !hexValue(d.CarrierHash, 32) || !hexValue(d.StateRoot, 32) || !hexValue(d.ObservationPolicy, 32) || !hexValue(d.Address, 20) || (d.View != "settled" && d.View != "recent_preview") {
		return nil, ErrReport
	}
	if _, err := integer(report.ChainID, false); err != nil {
		return nil, err
	}
	values := []string{d.CarrierHeight, d.Retention, d.From, d.Through, d.Eligible, d.ObservedPrepare, d.ObservedCommit, d.Minimum, d.Numerator, d.Denominator}
	numbers := make([]*big.Int, len(values))
	for i, v := range values {
		n, err := integer(v, i == 1 || i >= 7)
		if err != nil {
			return nil, err
		}
		numbers[i] = n
	}
	height, H, from, through, N, P, C, M, a, b := numbers[0], numbers[1], numbers[2], numbers[3], numbers[4], numbers[5], numbers[6], numbers[7], numbers[8], numbers[9]
	width := new(big.Int).Sub(new(big.Int).Add(through, big.NewInt(1)), from)
	if width.Sign() < 0 || through.Cmp(height) > 0 || width.Cmp(H) > 0 || N.Cmp(width) > 0 || P.Cmp(N) > 0 || C.Cmp(N) > 0 || M.Cmp(H) > 0 || a.Cmp(b) > 0 || !a.IsUint64() || !b.IsUint64() || new(big.Int).GCD(nil, nil, a, b).Cmp(big.NewInt(1)) != 0 {
		return nil, ErrReport
	}
	switch d.HistoryStatus {
	case "NO_HISTORY", "INSUFFICIENT_HISTORY", "SUFFICIENT_HISTORY":
	default:
		return nil, ErrReport
	}
	if d.ObservedBand != nil && *d.ObservedBand != "IN_OBSERVED_BAND" && *d.ObservedBand != "BELOW_OBSERVED_BAND" {
		return nil, ErrReport
	}
	math := &Arithmetic{HistoryStatus: "NO_HISTORY"}
	if N.Sign() > 0 {
		math.HistoryStatus = "INSUFFICIENT_HISTORY"
		if N.Cmp(M) >= 0 {
			math.HistoryStatus = "SUFFICIENT_HISTORY"
			// A rational oracle is independent of the producer's integer products.
			threshold := new(big.Rat).SetFrac(a, b)
			prepare := new(big.Rat).SetFrac(P, N)
			commit := new(big.Rat).SetFrac(C, N)
			band := "BELOW_OBSERVED_BAND"
			if prepare.Cmp(threshold) >= 0 && commit.Cmp(threshold) >= 0 {
				band = "IN_OBSERVED_BAND"
			}
			math.ObservedBand = &band
		}
	}
	math.MatchesReported = math.HistoryStatus == d.HistoryStatus && sameBand(math.ObservedBand, d.ObservedBand)
	out.Arithmetic = math
	return out, nil
}
