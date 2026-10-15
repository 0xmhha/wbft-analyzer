package scenario

import "github.com/0xmhha/wbft/conformance/sim"

// StaticChainConfiguration describes recorded inputs to the model. The source
// digest covers the source chain's parameters and rules. Generated simulator
// configurations have their own digest, including resolved per-node timing.
type StaticChainConfiguration struct {
	SourceRulesDigest      string            `json:"source_rules_digest,omitempty"`
	RuleActivations        map[string]string `json:"rule_activations"`
	AllowedFutureBlockTime uint64            `json:"allowed_future_block_time_seconds,string"`
}

func modeledStaticConfiguration(sc sim.Scenario) *StaticChainConfiguration {
	if len(sc.Params.RuleActivations) == 0 && (sc.Params.AllowedFutureBlockTime == nil || *sc.Params.AllowedFutureBlockTime == 0) {
		return nil
	}
	out := &StaticChainConfiguration{RuleActivations: map[string]string{}}
	for key, activation := range sc.Params.RuleActivations {
		out.RuleActivations[string(key)] = activation
	}
	if sc.Params.AllowedFutureBlockTime != nil {
		out.AllowedFutureBlockTime = *sc.Params.AllowedFutureBlockTime
	}
	return out
}
