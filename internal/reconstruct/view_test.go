package reconstruct

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft/consensus"
)

func TestViewComparisonUsesActualCoreContextAndAllEffectiveParameters(t *testing.T) {
	c, source := coreFixture(t)
	if _, err := c.step(source, consensus.Start{}); err != nil {
		t.Fatal(err)
	}
	got := computedView(c.env.cfg, c.state.Snapshot())
	want := recordedView(inputobs.View{Height: got.Height, Round: got.Round, State: "Accept request", Proposer: got.Proposer, ValsetDigest: got.Valset, Config: got.Parameters})
	if differences := viewDifferences(want, got, "after"); len(differences) != 0 {
		t.Fatal(differences)
	}
	copy := *want.Parameters
	copy.ProposerPolicy = "1"
	want.Parameters = &copy
	differences := viewDifferences(want, got, "after")
	if len(differences) != 1 || differences[0].Kind != "after_configuration" || got.Parameters.ProposerPolicy != "0" {
		t.Fatal("effective policy difference hidden or source mutated", differences)
	}
}

func TestViewComparisonDoesNotProjectAnUnknownSourceState(t *testing.T) {
	projection := recordedView(inputobs.View{Height: "1", Round: "0", State: "PRIVATE_RAW_STATE"})
	data, err := json.Marshal(projection)
	if err != nil || strings.Contains(string(data), "PRIVATE_RAW_STATE") || projection.State != "unavailable" {
		t.Fatal(string(data), err)
	}
}
