package reconstruct

import (
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/inputobs"
	"github.com/0xmhha/wbft/consensus"
	"github.com/0xmhha/wbft/types"
)

// observedCore owns one reconstructed engine. A failed application binding
// discards that engine: State.Step may already have changed private state.
// The caller must not publish its outputs or resume from that state.
type observedCore struct {
	state    *consensus.State
	env      *observedEnv
	instance string
	ordinal  uint64
	failed   *envFailure
}

func newObservedCore(cfg *types.Config, self types.Address, chain types.ChainReader) *observedCore {
	return &observedCore{
		state: consensus.NewState(consensus.Options{Config: cfg, Self: self, Improvements: 0}),
		env:   &observedEnv{chain: chain, cfg: cfg},
	}
}

func (c *observedCore) refuse(reason string) ([]consensus.Output, error) {
	failure := envFailure{Reason: reason}
	c.failed = &failure
	return nil, failure
}

// step consumes an input already bound by the input planner. It neither
// delivers a broadcast to self nor runs a scheduled input recursively.
// Timer generations and replay provenance remain the planner's responsibility.
func (c *observedCore) step(source inputobs.Input, in consensus.Input) (out []consensus.Output, err error) {
	return c.apply(source, boundInput{in: in})
}

func (c *observedCore) apply(source inputobs.Input, binding boundInput) (out []consensus.Output, err error) {
	in := binding.in
	if c.failed != nil {
		return nil, *c.failed
	}
	ordinal, parseErr := strconv.ParseUint(source.Ordinal, 10, 64)
	if parseErr != nil || strconv.FormatUint(ordinal, 10) != source.Ordinal || ordinal == 0 || c.ordinal == ^uint64(0) || c.ordinal != 0 && ordinal != c.ordinal+1 {
		return c.refuse("processing_input_sequence_unbound")
	}
	if c.ordinal == 0 {
		if source.Instance == "" || source.Kind != "start" {
			return c.refuse("processing_engine_start_unbound")
		}
		if _, ok := in.(consensus.Start); !ok {
			return c.refuse("processing_engine_start_unbound")
		}
		c.instance = source.Instance
	} else if source.Instance != c.instance {
		return c.refuse("processing_engine_instance_differs")
	} else if _, restart := in.(consensus.Start); restart {
		return c.refuse("processing_engine_restart_unbound")
	}
	c.ordinal = ordinal
	c.env.reset(source.Answers)
	defer func() {
		if recovered := recover(); recovered != nil {
			failure, ok := recovered.(envFailure)
			if !ok {
				panic(recovered)
			}
			c.failed = &failure
			out, err = nil, failure
		}
	}()
	if expiry := binding.future; expiry != nil {
		replay, ok := in.(consensus.Replay)
		if source.Kind != "backlog" || !ok || expiry.Kind != consensus.FutureTimer || expiry.Msg == nil || expiry.Msg != replay.Msg {
			return c.refuse("future_delivery_source_differs")
		}
		// This is an explicit composite of the observed backlog delivery,
		// not an invented second source record. The derived expiry may only
		// produce this exact queued replay and may not read application data.
		c.env.reset(nil)
		derived := c.state.Step(c.env, *expiry)
		if len(derived) != 1 {
			return c.refuse("future_delivery_schedule_differs")
		}
		scheduled, ok := derived[0].(consensus.Schedule)
		if !ok {
			return c.refuse("future_delivery_schedule_differs")
		}
		expected, ok := scheduled.In.(consensus.Replay)
		if !ok || expected.Msg != replay.Msg {
			return c.refuse("future_delivery_schedule_differs")
		}
		c.env.reset(source.Answers)
	}
	out = c.state.Step(c.env, in)
	if failure := c.env.finish(); failure != nil {
		closed, ok := failure.(envFailure)
		if !ok {
			panic(failure)
		}
		c.failed = &closed
		return nil, failure
	}
	return out, nil
}
