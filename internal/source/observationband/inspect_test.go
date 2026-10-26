package observationband

import (
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	wbftrpc "github.com/0xmhha/wbft/rpc"
)

func normal(t *testing.T) wbftrpc.ObservationBandResult {
	t.Helper()
	raw, err := os.ReadFile("testdata/normal-node-report.json")
	if err != nil {
		t.Fatal(err)
	}
	var report wbftrpc.ObservationBandResult
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	return report
}
func encode(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestInspectNormalReportedArithmeticAndIndependentScope(t *testing.T) {
	r := normal(t)
	out, err := Inspect(encode(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if out.SourceScope != "node_reported" || out.Arithmetic == nil || !out.Arithmetic.MatchesReported || out.Arithmetic.ObservedBand == nil || *out.Arithmetic.ObservedBand != "IN_OBSERVED_BAND" {
		t.Fatal(out)
	}
	// Neither plausible hash strings nor consistent arithmetic establish ancestry.
	r.Diagnostic.StateRoot = "0x" + strings.Repeat("1", 64)
	out, err = Inspect(encode(t, r))
	if err != nil || out.SourceScope != "node_reported" {
		t.Fatal("self-declared root became verified", err)
	}
	r = normal(t)
	r.Diagnostic.ObservedCommit = "2"
	out, err = Inspect(encode(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if out.Arithmetic.MatchesReported || *out.Arithmetic.ObservedBand != "BELOW_OBSERVED_BAND" {
		t.Fatal("phase arithmetic mismatch hidden", out)
	}
	r = normal(t)
	r.Diagnostic.Eligible = "2"
	r.Diagnostic.ObservedPrepare = "2"
	r.Diagnostic.ObservedCommit = "2"
	r.Diagnostic.HistoryStatus = "INSUFFICIENT_HISTORY"
	r.Diagnostic.ObservedBand = nil
	out, err = Inspect(encode(t, r))
	if err != nil || out.Arithmetic.HistoryStatus != "INSUFFICIENT_HISTORY" || out.Arithmetic.ObservedBand != nil || !out.Arithmetic.MatchesReported {
		t.Fatal(out, err)
	}
	r.Diagnostic.Eligible = "0"
	r.Diagnostic.ObservedPrepare = "0"
	r.Diagnostic.ObservedCommit = "0"
	r.Diagnostic.HistoryStatus = "NO_HISTORY"
	out, err = Inspect(encode(t, r))
	if err != nil || out.Arithmetic.HistoryStatus != "NO_HISTORY" || out.Arithmetic.ObservedBand != nil {
		t.Fatal(out, err)
	}
}

func TestInspectFullHeightEnvelopeAndAvailability(t *testing.T) {
	r := normal(t)
	height := new(big.Int).Lsh(big.NewInt(1), 128)
	r.Diagnostic.CarrierHeight = height.String()
	r.Diagnostic.Through = new(big.Int).Sub(height, big.NewInt(2)).String()
	r.Diagnostic.From = new(big.Int).Sub(height, big.NewInt(4)).String()
	envelope := struct {
		JSONRPC string                        `json:"jsonrpc"`
		ID      int                           `json:"id"`
		Result  wbftrpc.ObservationBandResult `json:"result"`
	}{"2.0", 1, r}
	out, err := Inspect(encode(t, envelope))
	if err != nil || out.Report.Diagnostic.CarrierHeight != height.String() || !out.Arithmetic.MatchesReported {
		t.Fatal(out, err)
	}
	for _, status := range []string{"UNAVAILABLE", "BEFORE_ACTIVATION", "DISABLED", "UNSUPPORTED"} {
		r = normal(t)
		r.Status = status
		r.Diagnostic = nil
		r.VerificationScope = ""
		out, err = Inspect(encode(t, r))
		if err != nil || out.Arithmetic != nil || out.Report.Diagnostic != nil {
			t.Fatal("unavailable data became zero observations", out, err)
		}
	}
}

func TestInspectClosedBoundedReport(t *testing.T) {
	for _, change := range []func(*wbftrpc.ObservationBandResult){
		func(r *wbftrpc.ObservationBandResult) { r.VerificationScope = "independent_chain_verification" },
		func(r *wbftrpc.ObservationBandResult) { r.Status = "PASS" },
		func(r *wbftrpc.ObservationBandResult) { r.Diagnostic.Eligible = "4" },
		func(r *wbftrpc.ObservationBandResult) { r.Diagnostic.ObservedCommit = "4" },
		func(r *wbftrpc.ObservationBandResult) { r.Diagnostic.Minimum = "4" },
		func(r *wbftrpc.ObservationBandResult) { r.Diagnostic.Minimum = "03" },
		func(r *wbftrpc.ObservationBandResult) { r.Diagnostic.Numerator = "8"; r.Diagnostic.Denominator = "10" },
		func(r *wbftrpc.ObservationBandResult) { r.Diagnostic.From = "99" },
		func(r *wbftrpc.ObservationBandResult) { r.Diagnostic.StateRoot = "unbound" },
		func(r *wbftrpc.ObservationBandResult) { r.Diagnostic.CarrierHeight = strings.Repeat("1", 257) },
	} {
		r := normal(t)
		change(&r)
		if _, err := Inspect(encode(t, r)); err == nil {
			t.Fatal("invalid report accepted")
		}
	}
	raw := encode(t, normal(t))
	raw = append(raw[:len(raw)-1], []byte(`,"verified":true}`)...)
	for _, bad := range [][]byte{raw, []byte("null"), []byte("[]"), []byte(strings.Repeat(" ", MaxReportBytes+1))} {
		if _, err := Inspect(bad); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
}
