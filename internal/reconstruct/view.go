package reconstruct

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

func sourceStateName(state string) string {
	switch state {
	case "Accept request", "AcceptRequest":
		return "AcceptRequest"
	case "Preprepared", "Prepared", "Committed":
		return state
	default:
		return "unavailable"
	}
}

func recordedView(view inputobs.View) Projection {
	running := view.Height != ""
	p := Projection{Kind: "state", Running: &running}
	if running {
		p.Height, p.Round, p.State, p.Proposer, p.Valset, p.Parameters = view.Height, view.Round, sourceStateName(view.State), view.Proposer, view.ValsetDigest, view.Config
	}
	return p
}

func computedView(cfg *types.Config, view *consensus.Snapshot) Projection {
	running := view != nil && view.Running
	p := Projection{Kind: "state", Running: &running}
	if !running {
		return p
	}
	p.Height, p.Round, p.State = view.View.Sequence.String(), view.View.Round.String(), view.State.String()
	p.Proposer, p.Valset = strings.ToLower(view.Proposer.Hex()), strings.ToLower(consensus.ValsetDigest(view.Validators).Hex())
	if cfg != nil {
		parameters := cfg.ConfigAt(view.View.Sequence)
		if parameters.ProposerPolicy != nil {
			u := func(value uint64) string { return strconv.FormatUint(value, 10) }
			p.Parameters = &inputobs.Parameters{RequestTimeoutMS: u(parameters.RequestTimeoutMs), BlockPeriodSeconds: u(parameters.BlockPeriodSeconds), Epoch: u(parameters.EpochLength), MaxRequestTimeoutSeconds: u(parameters.MaxRequestTimeoutSeconds), AllowedFutureBlockSeconds: u(parameters.AllowedFutureBlockTime), ProposerPolicy: u(parameters.ProposerPolicy.ID)}
		}
	}
	return p
}

func viewDifferences(expected, actual Projection, phase string) []DifferenceCandidate {
	result := []DifferenceCandidate{}
	add := func(kind string, want, got Projection) {
		want.Kind, got.Kind = "state", "state"
		result = append(result, DifferenceCandidate{Kind: phase + "_" + kind, Expected: &want, Actual: &got})
	}
	if !reflect.DeepEqual(expected.Running, actual.Running) {
		add("running", Projection{Running: expected.Running}, Projection{Running: actual.Running})
	}
	for _, field := range []struct{ name, want, got string }{{"height", expected.Height, actual.Height}, {"round", expected.Round, actual.Round}, {"state", expected.State, actual.State}, {"proposer", expected.Proposer, actual.Proposer}, {"validator_set", expected.Valset, actual.Valset}} {
		if field.want != field.got {
			// This is a closed field name and a typed normalized value. An
			// arbitrary source field map or raw error is never projected.
			want, got := Projection{Kind: field.name}, Projection{Kind: field.name}
			switch field.name {
			case "height":
				want.Height, got.Height = field.want, field.got
			case "round":
				want.Round, got.Round = field.want, field.got
			case "state":
				want.State, got.State = field.want, field.got
			case "proposer":
				want.Proposer, got.Proposer = field.want, field.got
			case "validator_set":
				want.Valset, got.Valset = field.want, field.got
			}
			add(field.name, want, got)
		}
	}
	if !reflect.DeepEqual(expected.Parameters, actual.Parameters) {
		add("configuration", Projection{Parameters: expected.Parameters}, Projection{Parameters: actual.Parameters})
	}
	return result
}
