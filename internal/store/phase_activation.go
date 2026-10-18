package store

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strings"

	native "github.com/0xmhha/wbft/rpc"
)

var activationHeight = regexp.MustCompile(`^(0|[1-9][0-9]{0,155})$`)
var activationSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
var ErrPhaseActivation = errors.New("choose a completed run and a source-backed reported rule from a completed capture on the same network")

type PhaseActivationComparison struct {
	Key             string             `json:"key"`
	From            string             `json:"from"`
	Metric          string             `json:"metric"`
	CaptureName     string             `json:"capture_name"`
	Capture         ObservationCapture `json:"capture"`
	DeclarationCall int64              `json:"declaration_call"`
	Before          *PhaseComparison   `json:"before"`
	After           PhaseComparison    `json:"after"`
	ContextRecords  int64              `json:"context_records"`
	Method          string             `json:"method"`
}

// PhaseActivationComparison aligns one run to a recorded declaration, not to
// independently verified execution or an inferred observer/node identity.
func (s *Store) PhaseActivationComparison(ctx context.Context, network, dataset, captureID int64, key string, before, after int, node, metric string) (PhaseActivationComparison, error) {
	out := PhaseActivationComparison{Key: key, Metric: metric, Method: "descriptive before/at-or-after numeric full-height windows around a source-backed recorded rule declaration; the capture node is not inferred to be a run observer; declarations do not establish historical execution or causal improvement; null before means activation height zero; separate observer/profile/clock groups; combined context limit 100000"}
	if key == "" || len(key) > 128 || before < 1 || after < 1 || before > 100000 || after > 100000 {
		return out, ErrPhaseActivation
	}
	datasets, err := s.Datasets(ctx, network)
	if err != nil {
		return out, err
	}
	runOK, captureOK := false, false
	for _, d := range datasets {
		if d.ID == dataset {
			runOK = d.Kind == "run" && d.Status == "complete"
		}
		if d.ID == captureID {
			captureOK = d.Kind == "observations" && d.Status == "complete"
			out.CaptureName = d.Name
		}
	}
	if !runOK || !captureOK {
		return out, ErrPhaseActivation
	}
	capture, err := s.ObservationCapture(ctx, captureID)
	if errors.Is(err, ErrNotFound) {
		return out, ErrPhaseActivation
	}
	if err != nil {
		return out, err
	}
	identity, err := s.Network(ctx, network)
	if err != nil {
		return out, err
	}
	if capture.DatasetID != captureID || !oneSourceKind(capture.SourceKind) || !activationSHA.MatchString(capture.SourceSHA256) || !activationSHA.MatchString(capture.Snapshot) || capture.Node.ChainID != identity.ChainID || capture.Node.GenesisHash != identity.GenesisHash {
		return out, ErrPhaseActivation
	}
	from, declared := capture.Node.RuleActivations[key]
	if !declared || !activationHeight.MatchString(from) {
		return out, ErrPhaseActivation
	}
	// Require the selected declaration and identity to agree with its original normalized call.
	ordinal := int64(0)
	for _, call := range capture.Calls {
		if call.Method != "wbft_nodeInfo" {
			continue
		}
		if ordinal != 0 || call.Status != "available" || len(call.Params) != 0 {
			return out, ErrPhaseActivation
		}
		source, e := s.ObservationCall(ctx, captureID, call.Ordinal)
		if errors.Is(e, ErrNotFound) {
			return out, ErrPhaseActivation
		}
		if e != nil {
			return out, e
		}
		if source.Method != call.Method || source.Status != call.Status || source.Ordinal != call.Ordinal || len(source.Params) != 0 || !activationSHA.MatchString(call.SHA256) || source.SHA256 != call.SHA256 {
			return out, ErrPhaseActivation
		}
		var claim native.NodeInfo
		if json.Unmarshal(source.Data, &claim) != nil || claim.ChainID == nil {
			return out, ErrPhaseActivation
		}
		value, present := "", false
		for k, v := range claim.RuleActivations {
			if string(k) == key {
				value, present = v, true
			}
		}
		if !present || value != from || claim.ChainID.String() != capture.Node.ChainID || claim.GenesisHash.String() != capture.Node.GenesisHash || !strings.EqualFold(claim.Address.String(), capture.Node.Address) || claim.RulesDigest.String() != capture.Node.RulesDigest || claim.Head.Number != capture.Node.HeadNumber || claim.Head.Hash.String() != capture.Node.HeadHash || claim.LogProfile != capture.Node.LogProfile {
			return out, ErrPhaseActivation
		}
		ordinal = call.Ordinal
	}
	if ordinal == 0 {
		return out, ErrPhaseActivation
	}
	activation, _ := new(big.Int).SetString(from, 10)
	first := new(big.Int).Sub(activation, big.NewInt(int64(before)))
	if first.Sign() < 0 {
		first.SetInt64(0)
	}
	last := new(big.Int).Add(activation, big.NewInt(int64(after-1)))
	span := new(big.Int).Sub(last, first)
	span.Add(span, big.NewInt(1))
	if len(last.String()) > 156 || span.Cmp(big.NewInt(100000)) > 0 {
		return out, ErrPhaseActivation
	}
	out.From, out.Capture, out.DeclarationCall = from, capture, ordinal
	if activation.Sign() > 0 {
		end := new(big.Int).Sub(activation, big.NewInt(1))
		result, e := s.phaseRange(ctx, network, []int64{dataset}, first.String(), end.String(), node, metric, false, 100000)
		if e != nil {
			return out, e
		}
		out.Before = &result
		out.ContextRecords = result.ContextRecords
	}
	result, err := s.phaseRange(ctx, network, []int64{dataset}, from, last.String(), node, metric, false, 100000-int(out.ContextRecords))
	if err != nil {
		return out, err
	}
	out.After = result
	out.ContextRecords += result.ContextRecords
	return out, nil
}
