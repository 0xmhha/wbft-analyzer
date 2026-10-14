package whatif

import (
	"encoding/json"
	"github.com/0xmhha/wbft/observe/event"
	"regexp"
	"strconv"
)

// Action is an output fingerprint, never a transmission or arrival claim.
// Eligible recipients describe membership intent; payload bytes stay retained.
type Action struct {
	Output            string    `json:"output"`
	Kind              string    `json:"kind"`
	SHA256            string    `json:"output_sha256"`
	Height            *string   `json:"height,omitempty"`
	Round             *string   `json:"round,omitempty"`
	Code              string    `json:"code,omitempty"`
	Event             string    `json:"event,omitempty"`
	Timer             string    `json:"timer,omitempty"`
	Duration          *string   `json:"duration_ns,omitempty"`
	CancelKinds       []string  `json:"cancel_kinds,omitempty"`
	Recipients        []string  `json:"eligible_recipients"`
	RecipientEvidence string    `json:"recipient_evidence"`
	PayloadSHA256     string    `json:"payload_sha256,omitempty"`
	PayloadEvidence   string    `json:"payload_evidence"`
	SigningInput      *Source   `json:"signing_input,omitempty"`
	SigningOutput     *Question `json:"signing_output,omitempty"`
	Application       *Question `json:"application_question,omitempty"`
}

var actionHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var addressPattern = regexp.MustCompile(`^0x[0-9a-f]{40}$`)

func (a Action) validate(index int) error {
	if a.Kind != "event" && a.Event != "" || a.Kind != "arm_timer" && (a.Timer != "" || a.Duration != nil) || a.Kind != "cancel_timers" && len(a.CancelKinds) > 0 {
		return ErrEvidence
	}
	if a.Code != "" && a.Kind != "broadcast" && a.Kind != "relay" && a.Kind != "outcome" {
		return ErrEvidence
	}
	if a.Height != nil && a.Kind != "broadcast" && a.Kind != "arm_timer" && a.Kind != "request_build" && a.Kind != "commit" && a.Kind != "outcome" {
		return ErrEvidence
	}
	if a.Output != strconv.Itoa(index+1) || !actionHashPattern.MatchString(a.SHA256) || a.Recipients == nil || len(a.Recipients) > 10000 || !sourceValid(a.SigningInput) {
		return ErrEvidence
	}
	if (a.Height == nil) != (a.Round == nil) || a.Height != nil && (!decimal(*a.Height, true, 512) || !decimal(*a.Round, true, 512)) {
		return ErrEvidence
	}
	if a.Code != "" && !decimal(a.Code, true, 64) || a.Timer != "" && !decimal(a.Timer, true, 8) || a.Duration != nil && !decimal(*a.Duration, true, 63) {
		return ErrEvidence
	}
	seen := map[string]bool{}
	for _, address := range a.Recipients {
		if !addressPattern.MatchString(address) || seen[address] {
			return ErrEvidence
		}
		seen[address] = true
	}
	for _, kind := range a.CancelKinds {
		if !decimal(kind, true, 8) {
			return ErrEvidence
		}
	}
	for _, q := range []*Question{a.SigningOutput, a.Application} {
		if q != nil && (!sourceValid(&q.Source) || !decimal(q.Output, false, 64)) {
			return ErrEvidence
		}
	}
	if a.PayloadSHA256 != "" && !actionHashPattern.MatchString(a.PayloadSHA256) {
		return ErrEvidence
	}
	switch a.Kind {
	case "broadcast", "relay":
		if a.RecipientEvidence != "validator_set" && a.RecipientEvidence != "unknown" || a.RecipientEvidence == "unknown" && len(a.Recipients) != 0 || a.Code == "" || a.Application != nil {
			return ErrEvidence
		}
		if a.Kind == "relay" {
			if a.PayloadEvidence != "core_relay_bytes" || a.PayloadSHA256 == "" || a.SigningInput != nil || a.SigningOutput != nil {
				return ErrEvidence
			}
		} else {
			if a.Height == nil {
				return ErrEvidence
			}
			switch a.PayloadEvidence {
			case "unsigned_request":
				if a.PayloadSHA256 != "" || a.SigningInput != nil || a.SigningOutput != nil {
					return ErrEvidence
				}
			case "recorded_signing_result":
				if a.PayloadSHA256 == "" || a.SigningInput == nil || a.SigningOutput == nil {
					return ErrEvidence
				}
			case "recorded_signing_failure":
				if a.PayloadSHA256 != "" || a.SigningInput == nil || a.SigningOutput == nil {
					return ErrEvidence
				}
			default:
				return ErrEvidence
			}
		}
	case "schedule", "arm_timer", "cancel_timers", "request_build", "commit", "outcome", "event":
		if a.RecipientEvidence != "not_network" || a.PayloadEvidence != "not_network" || len(a.Recipients) != 0 || a.PayloadSHA256 != "" || a.SigningInput != nil || a.SigningOutput != nil {
			return ErrEvidence
		}
		if a.Application != nil && a.Kind != "request_build" && a.Kind != "commit" {
			return ErrEvidence
		}
		if a.Kind == "arm_timer" && (a.Timer == "" || a.Duration == nil || a.Height == nil) {
			return ErrEvidence
		}
		if (a.Kind == "commit" || a.Kind == "request_build") && (a.Application == nil || a.Height == nil) {
			return ErrEvidence
		}
		if a.Kind == "event" && !event.IsNodeKind(event.Kind(a.Event)) {
			return ErrEvidence
		}
	default:
		return ErrEvidence
	}
	return nil
}

func (s Step) validateActions() error {
	// Historical stored rows predate action evidence. New helper envelopes
	// must contain all three fields; DecodeStep refuses missing/null arrays.
	if s.Actions == nil && s.RecordedActions == nil && s.ParentOutput == "" {
		return nil
	}
	if s.Actions == nil || s.RecordedActions == nil || len(s.Actions) != s.Outputs || len(s.RecordedActions) > 100000 || s.Generated && len(s.RecordedActions) != 0 || !decimal(s.ParentOutput, true, 64) {
		return ErrEvidence
	}
	if s.Generated && s.ParentOutput == "0" || !s.Generated && s.ParentOutput != "0" {
		return ErrEvidence
	}
	for _, actions := range [][]Action{s.Actions, s.RecordedActions} {
		for index, action := range actions {
			if err := action.validate(index); err != nil {
				return err
			}
		}
	}
	return nil
}

// actionIdentity includes all evidence fields except a changed execution's
// own output number. It never compares only an unsigned message digest.
func actionIdentity(a Action) string {
	a.Output = ""
	raw, _ := json.Marshal(a)
	return string(raw)
}

func parseOutput(value string, size int) (int, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n == 0 || n > uint64(size) {
		return 0, ErrEvidence
	}
	return int(n) - 1, nil
}
