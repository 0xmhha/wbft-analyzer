package reexec

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/conformance/stepdriver"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

// Decimal strings preserve full source coordinates across browser clients.
type InputSchedule struct {
	Action string `json:"action" enum:"drop,delay,swap"`
	Writer string `json:"writer_run"`
	Engine string `json:"engine_run"`
	Step   string `json:"step"`
	Other  string `json:"other_step,omitempty"`
}

func (s *InputSchedule) UnmarshalJSON(raw []byte) error {
	if len(raw) > 4096 {
		return ErrHelper
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return ErrHelper
	}
	seen := map[string]bool{}
	for d.More() {
		t, e := d.Token()
		k, ok := t.(string)
		if e != nil || !ok || seen[k] {
			return ErrHelper
		}
		seen[k] = true
		switch k {
		case "action", "writer_run", "engine_run", "step", "other_step":
		default:
			return ErrHelper
		}
		var value string
		if d.Decode(&value) != nil {
			return ErrHelper
		}
	}
	if t, e := d.Token(); e != nil || t != json.Delim('}') {
		return ErrHelper
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrHelper
	}
	type plain InputSchedule
	var p plain
	if json.Unmarshal(raw, &p) != nil {
		return ErrHelper
	}
	*s = InputSchedule(p)
	_, err = s.core()
	return err
}
func decimal(s string) (uint64, error) {
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != s {
		return 0, ErrHelper
	}
	return n, nil
}
func (s InputSchedule) core() (*stepdriver.TraceSchedule, error) {
	if !logs.Identifier(s.Writer) {
		return nil, ErrHelper
	}
	engine, e := decimal(s.Engine)
	if e != nil {
		return nil, e
	}
	step, e := decimal(s.Step)
	if e != nil {
		return nil, e
	}
	var other uint64
	if s.Other != "" {
		other, e = decimal(s.Other)
		if e != nil {
			return nil, e
		}
	}
	switch s.Action {
	case "drop":
		if other != 0 {
			return nil, ErrHelper
		}
	case "delay":
		if other <= step {
			return nil, ErrHelper
		}
	case "swap":
		if other == 0 || other == step {
			return nil, ErrHelper
		}
	default:
		return nil, ErrHelper
	}
	return &stepdriver.TraceSchedule{Action: s.Action, WriterRun: s.Writer, EngineRun: engine, Step: step, OtherStep: other}, nil
}

type InputPosition struct {
	Writer        string `json:"writer_run"`
	Engine        string `json:"engine_run"`
	Step          string `json:"step"`
	Ordinal       int64  `json:"reader_ordinal"`
	SourceSeq     string `json:"source_seq"`
	ExecutionStep string `json:"execution_step"`
	SlotStep      string `json:"slot_step"`
	SlotOrdinal   int64  `json:"slot_reader_ordinal"`
	SlotSeq       string `json:"slot_source_seq"`
	Removed       bool   `json:"removed,omitempty"`
}

func inputPosition(p stepdriver.TraceInputPosition) *InputPosition {
	return &InputPosition{Writer: p.WriterRun, Engine: strconv.FormatUint(p.EngineRun, 10), Step: strconv.FormatUint(p.Step, 10), Ordinal: int64(p.Ordinal), SourceSeq: strconv.FormatUint(p.JSeq, 10), ExecutionStep: strconv.FormatUint(p.ExecutionStep, 10), SlotStep: strconv.FormatUint(p.SlotStep, 10), SlotOrdinal: int64(p.SlotOrdinal), SlotSeq: strconv.FormatUint(p.SlotJSeq, 10), Removed: p.Removed}
}
func scheduleExecution(p Plan, change *InputSchedule) (executionPlan, error) {
	out := executionPlan{}
	c, err := change.core()
	if err != nil {
		return out, err
	}
	rd, err := journal.OpenReader(nil, p.Input.Input.Path)
	if err != nil {
		return out, err
	}
	positions, err := stepdriver.PlanTraceSchedule(rd, *c)
	if err != nil {
		return out, err
	}
	source := map[int64]Step{}
	for _, s := range p.Steps {
		source[s.Ordinal] = s
	}
	if len(positions) != len(p.Steps) {
		return out, ErrHelper
	}
	selected := map[string]bool{}
	for _, h := range p.Heights {
		selected[h.Number] = true
	}
	out.firstSelected = len(positions)
	affected := false
	for i, pos := range positions {
		s, ok := source[int64(pos.Ordinal)]
		slot, exists := source[int64(pos.SlotOrdinal)]
		if !ok || !exists || s.Run != pos.WriterRun || s.Engine != strconv.FormatUint(pos.EngineRun, 10) || s.Number != strconv.FormatUint(pos.Step, 10) || slot.Number != strconv.FormatUint(pos.SlotStep, 10) {
			return out, ErrHelper
		}
		if pos.Removed || pos.Ordinal != pos.SlotOrdinal {
			affected = true
		}
		s.scheduleAffected = affected
		s.Scheduled = inputPosition(pos)
		s.ExecutionOrdinal = int64(pos.SlotOrdinal)
		s.ExecutionHeight = slot.Height
		out.steps = append(out.steps, s)
		if selected[slot.Height] && out.firstSelected == len(positions) {
			out.firstSelected = i
		}
	}
	return out, nil
}
func (s Step) activeHeight() string {
	if s.ExecutionHeight != "" {
		return s.ExecutionHeight
	}
	return s.Height
}
func (s Step) contextOrdinal() int64 {
	if s.Scheduled != nil {
		return s.Scheduled.SlotOrdinal
	}
	return s.Ordinal
}
func (s Step) Cursor() int64 {
	if s.ExecutionOrdinal > 0 {
		return s.ExecutionOrdinal
	}
	return s.Ordinal
}

func emptyOutputDigest() string { d, _ := inputlog.OutDigest(nil); return digest(d) }
