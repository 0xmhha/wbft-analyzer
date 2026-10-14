package whatif

import (
	"bytes"
	"encoding/json"
	"io"
)

// DecodeStep bounds and validates a helper message before storage. Unknown
// fields cannot silently carry new payloads through this metadata boundary.
func DecodeStep(raw []byte, previous uint64) (Step, error) {
	var s Step
	var envelope struct {
		Type string `json:"type"`
		ID   uint64 `json:"id"`
		Step
	}
	if len(raw) > 64<<10 {
		return s, ErrEvidence
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	if rejectDuplicateKeys(check, 0) != nil {
		return s, ErrEvidence
	}
	if _, err := check.Token(); err != io.EOF {
		return s, ErrEvidence
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return s, ErrEvidence
	}
	for _, key := range []string{"type", "id", "execution_step", "t_mono_ns", "execution_state", "source_input", "generated", "counterfactual", "execution_model", "comparable", "match", "outputs", "out_digest", "output_actions", "recorded_output_actions", "parent_output"} {
		value, ok := fields[key]
		if !ok || key != "source_input" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return s, ErrEvidence
		}
	}
	var stateFields map[string]json.RawMessage
	if json.Unmarshal(fields["execution_state"], &stateFields) != nil {
		return s, ErrEvidence
	}
	if value, ok := stateFields["running"]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return s, ErrEvidence
	}
	if _, ok := stateFields["height"]; !ok {
		return s, ErrEvidence
	}
	if _, ok := stateFields["round"]; !ok {
		return s, ErrEvidence
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil {
		return s, ErrEvidence
	}
	if _, err := d.Token(); err != io.EOF {
		return s, ErrEvidence
	}
	if envelope.Type != "timed_step" || envelope.ID != 1 {
		return s, ErrEvidence
	}
	s = envelope.Step
	if err := s.Validate(previous); err != nil {
		return s, err
	}
	return s, nil
}

func rejectDuplicateKeys(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrEvidence
	}
	token, err := d.Token()
	if err != nil {
		return ErrEvidence
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			keyToken, err := d.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] {
				return ErrEvidence
			}
			seen[key] = true
			if rejectDuplicateKeys(d, depth+1) != nil {
				return ErrEvidence
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim('}') {
			return ErrEvidence
		}
	case '[':
		for d.More() {
			if rejectDuplicateKeys(d, depth+1) != nil {
				return ErrEvidence
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim(']') {
			return ErrEvidence
		}
	default:
		return ErrEvidence
	}
	return nil
}

// DecodeJSON applies the metadata boundary rules to operator requests too.
func DecodeJSON(raw []byte, destination any) error {
	if len(raw) > 4096 || rejectDuplicateKeys(json.NewDecoder(bytes.NewReader(raw)), 0) != nil {
		return ErrEvidence
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return ErrEvidence
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrEvidence
	}
	return nil
}
