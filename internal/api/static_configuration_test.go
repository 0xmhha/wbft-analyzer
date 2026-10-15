package api

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
)

func TestStaticConfigurationContractPreservesIntegerPrecisionAndEvidenceScope(t *testing.T) {
	s := loadSpec(t)
	value := scenario.StaticChainConfiguration{RuleActivations: map[string]string{"rejectNumberJump": "340282366920938463463374607431768211456"}, AllowedFutureBlockTime: math.MaxUint64}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["allowed_future_block_time_seconds"] != "18446744073709551615" || decoded["rule_activations"].(map[string]any)["rejectNumberJump"] != "340282366920938463463374607431768211456" {
		t.Fatal("integer precision lost", decoded)
	}
	ref := map[string]any{"$ref": "#/components/schemas/ScenarioStaticChainConfiguration"}
	if err := s.check(decoded, ref, "$"); err != nil {
		t.Fatal(err)
	}
	decoded["allowed_future_block_time_seconds"] = json.Number("18446744073709551615")
	if err := s.check(decoded, ref, "$"); err == nil {
		t.Fatal("numeric future allowance admitted")
	}
	decoded["allowed_future_block_time_seconds"] = "0"
	decoded["rule_activations"].(map[string]any)["rejectNumberJump"] = json.Number("0")
	if err := s.check(decoded, ref, "$"); err == nil {
		t.Fatal("numeric activation admitted")
	}
}
