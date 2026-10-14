package runtimeobs

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEngineProjectionPreservesOriginalIDsAndStageParents(t *testing.T) {
	raw := engineInput([]string{"start_enter", "subscribed", "handler_enter", "initial_round_return", "start_return", "stop_enter", "timers_stopped", "unsubscribed", "handler_exit", "handler_joined", "stop_return"})
	c, e := FromReader(strings.NewReader(raw))
	if e != nil || len(c.Engines) != 1 || len(c.Engines[0].Stages) != 11 || c.Engines[0].State != "observed_stopped" {
		t.Fatal(c, e)
	}
	b, e := json.Marshal(c.Engines[0])
	if e != nil || !strings.Contains(string(b), `"id":"18446744073709551615"`) || !strings.Contains(string(b), `"parent_id":"2"`) {
		t.Fatal(string(b), e)
	}
	old, e := FromReader(strings.NewReader(fixture()))
	if e != nil || len(old.Engines) != 0 || old.RuntimeModelComplete {
		t.Fatal(old, e)
	}
}

func TestPerInstanceConfigurationProjectionKeepsPrecisionAndCandidates(t *testing.T) {
	c, e := FromReader(strings.NewReader(configInput(t, false)))
	if e != nil || c.Normalizer != "wbft-runtime-observations/4" || len(c.Startups) != 1 || c.Engines[0].Configuration != "observed" || len(c.Engines[0].Configs) != 1 {
		t.Fatal(c, e)
	}
	p := c.Engines[0].Configs[0]
	if p.ID != "18446744073709551615" || p.ParentID != "1" || p.Config == nil || p.Config.Height != "18446744073709551616" {
		t.Fatal(p)
	}
	c, e = FromReader(strings.NewReader(configInput(t, true)))
	if e != nil || c.Engines[0].Configuration != "ambiguous" || len(c.Engines[0].Configs) != 2 {
		t.Fatal("configuration candidate lost", c, e)
	}
}
