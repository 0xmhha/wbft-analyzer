package whatif

import (
	"errors"
	"math/big"
	"regexp"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
)

var ErrEvidence = errors.New("invalid timed experiment evidence")
var digestPattern = regexp.MustCompile(`^0x[0-9a-f]{64}$`)

func decimal(value string, zero bool, bits int) bool {
	if value == "" || len(value) > 156 || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, ok := new(big.Int).SetString(value, 10)
	return ok && (zero || n.Sign() > 0) && n.BitLen() <= bits
}
func sourceValid(s *Source) bool {
	return s == nil || logs.Identifier(s.Writer) && decimal(s.Engine, false, 64) && decimal(s.Step, false, 64) && decimal(s.Ordinal, false, 64)
}

// Validate refuses fabricated source positions and rounded or inconsistent
// coordinates before results cross the storage or HTTP boundary.
func (s Step) Validate(previous uint64) error {
	n, err := strconv.ParseUint(s.Execution, 10, 64)
	if err != nil || !decimal(s.Execution, false, 64) || previous == ^uint64(0) || n != previous+1 || !decimal(s.Mono, true, 63) || !decimal(s.Parent, true, 64) || !decimal(s.ArmExecution, true, 64) {
		return ErrEvidence
	}
	parent, _ := strconv.ParseUint(s.Parent, 10, 64)
	arm, _ := strconv.ParseUint(s.ArmExecution, 10, 64)
	if parent >= n || arm >= n || !sourceValid(s.Source) || !sourceValid(s.Cause) || !sourceValid(s.Arm) || !sourceValid(s.Signing) {
		return ErrEvidence
	}
	if s.Generated != (s.Source == nil) || !s.Counterfactual || s.Model != Model || !digestPattern.MatchString(s.Digest) || s.Outputs < 0 || s.Outputs > 100000 {
		return ErrEvidence
	}
	if s.Suppression != "" {
		if s.Suppression != "regenerated_internal" || s.Source == nil || s.Generated || s.Input != "" || s.Outputs != 0 {
			return ErrEvidence
		}
	} else {
		switch s.Input {
		case "start", "stop", "new_head", "request", "message", "backlog", "timeout", "commit_result", "broadcast_failed", "peer_connected":
		default:
			return ErrEvidence
		}
	}
	if s.Generated && (s.Cause == nil || parent == 0) {
		return ErrEvidence
	}
	if s.Signing != nil && (!s.Generated || s.Input != "message") {
		return ErrEvidence
	}
	if s.Comparable && (s.Generated || s.Suppression != "") {
		return ErrEvidence
	}
	if s.State.Running {
		if s.State.Height == nil || s.State.Round == nil || !decimal(*s.State.Height, true, 512) || !decimal(*s.State.Round, true, 512) {
			return ErrEvidence
		}
		switch s.State.Name {
		case "AcceptRequest", "Preprepared", "Prepared", "Committed":
		default:
			return ErrEvidence
		}
	} else if s.State.Height != nil || s.State.Round != nil || s.State.Name != "" {
		return ErrEvidence
	}
	if s.Deadline != nil && (!decimal(*s.Deadline, true, 63) || s.Arm == nil || arm == 0) {
		return ErrEvidence
	}
	if len(s.Answers) > 100000 {
		return ErrEvidence
	}
	for _, a := range s.Answers {
		if !logs.Identifier(a.Writer) || !decimal(a.Engine, false, 64) || !decimal(a.Step, false, 64) || a.Call < 1 || a.Kind < 1 || a.Kind > 3 || !digestPattern.MatchString(a.Key) {
			return ErrEvidence
		}
	}
	if len(s.Questions) > 100000 {
		return ErrEvidence
	}
	for _, q := range s.Questions {
		if !sourceValid(&q.Source) || !decimal(q.Output, false, 64) {
			return ErrEvidence
		}
	}
	return nil
}
