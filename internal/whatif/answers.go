package whatif

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
)

// MarshalJSON exposes exact coordinates even though the helper wire protocol
// uses integer engine and step values. Keys remain internal verification data.
func (a Answer) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Writer string `json:"writer_run"`
		Engine string `json:"engine_run"`
		Step   string `json:"step"`
		Call   int    `json:"call"`
		Kind   int    `json:"kind"`
	}{a.Writer, a.Engine, a.Step, a.Call, a.Kind})
}

type RecordedAnswer struct {
	Source Source
	Call   int
	Kind   uint8
	Key    string
}

// WithAnswers adds only recorded answer references. No answer payload enters
// the index, and unknown calls or keys cannot be accepted by position alone.
func (e *Evidence) WithAnswers(records []RecordedAnswer) error {
	if e == nil || len(records) > 1000000 {
		return ErrEvidence
	}
	e.recorded = map[answerKey]RecordedAnswer{}
	for _, r := range records {
		if !e.sources[r.Source] || r.Call < 1 || r.Kind < 1 || r.Kind > 3 || !digestPattern.MatchString(r.Key) {
			return ErrEvidence
		}
		key := answerKey{answerCoordinate{r.Source.Writer, r.Source.Engine, r.Source.Step}, r.Call}
		if _, exists := e.recorded[key]; exists {
			return ErrEvidence
		}
		e.recorded[key] = r
	}
	return nil
}

func (a *Answer) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Writer string          `json:"writer_run"`
		Engine json.RawMessage `json:"engine_run"`
		Step   json.RawMessage `json:"step"`
		Call   int             `json:"call"`
		Kind   uint8           `json:"kind"`
		Key    string          `json:"key"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if rejectDuplicateKeys(json.NewDecoder(bytes.NewReader(raw)), 0) != nil || d.Decode(&wire) != nil {
		return ErrEvidence
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrEvidence
	}
	parse := func(raw json.RawMessage) (uint64, error) {
		value := string(raw)
		if len(raw) > 0 && raw[0] == '"' {
			if json.Unmarshal(raw, &value) != nil {
				return 0, ErrEvidence
			}
		}
		if !decimal(value, false, 64) {
			return 0, ErrEvidence
		}
		return strconv.ParseUint(value, 10, 64)
	}
	engine, err := parse(wire.Engine)
	if err != nil {
		return err
	}
	step, err := parse(wire.Step)
	if err != nil {
		return err
	}
	*a = Answer{wire.Writer, strconv.FormatUint(engine, 10), strconv.FormatUint(step, 10), wire.Call, int(wire.Kind), wire.Key}
	return nil
}
