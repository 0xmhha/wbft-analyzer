package scenario

import (
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
	"github.com/0xmhha/wbft/types"
)

type RuntimeObservation struct {
	Source  Input              `json:"source"`
	Capture runtimeobs.Capture `json:"-"`
}
type RuntimeConfiguration struct {
	EngineID   string           `json:"engine_id"`
	ParentID   string           `json:"parent_id"`
	State      string           `json:"state"`
	Point      runtimeobs.Point `json:"point"`
	Comparison string           `json:"comparison"`
}
type RuntimeBinding struct {
	Startups               []runtimeobs.Point     `json:"startups"`
	Configurations         []RuntimeConfiguration `json:"configurations"`
	EngineStates           map[string]int         `json:"engine_states"`
	TaskStates             map[string]int         `json:"task_states"`
	Source                 Input                  `json:"source"`
	Run                    string                 `json:"run"`
	Startup                *runtimeobs.Point      `json:"startup"`
	Configuration          string                 `json:"configuration"`
	CaptureComplete        bool                   `json:"capture_complete"`
	Calls                  []runtimeobs.Call      `json:"-"`
	CallCount              int                    `json:"call_count"`
	Unavailable            []string               `json:"unavailable"`
	ExecutionModelComplete bool                   `json:"execution_model_complete"`
}

func InspectRuntimeObservation(source Input, r io.Reader) (RuntimeObservation, error) {
	out := RuntimeObservation{Source: source}
	if source.Kind != "runtime" || !logs.Identifier(source.ID) || !hexLength(source.SHA256, 64) {
		return out, errors.New("invalid runtime source")
	}
	c, e := runtimeobs.FromReader(r)
	if e != nil {
		return out, e
	}
	if c.SourceSHA != source.SHA256 || c.Node != source.Node {
		return out, errors.New("runtime source identity mismatch")
	}
	out.Capture = c
	return out, nil
}

// BindRuntimeObservation verifies startup scalars at their recorded height.
// It never converts these measurements into native engine options or app timing.
func BindRuntimeObservation(in RuntimeObservation, cfg *types.Config, nodes []string) (RuntimeBinding, error) {
	c := in.Capture
	out := RuntimeBinding{Startups: runtimeobs.StartupCandidates(c), Configurations: []RuntimeConfiguration{}, EngineStates: map[string]int{}, TaskStates: map[string]int{}, Source: in.Source, Run: c.Run, Configuration: "unavailable", CaptureComplete: c.Complete, Calls: c.Calls, CallCount: len(c.Calls), Unavailable: c.Unavailable}
	if cfg == nil || in.Source.Node != c.Node || in.Source.SHA256 != c.SourceSHA {
		return out, errors.New("invalid runtime binding")
	}
	for _, engine := range c.Engines {
		out.EngineStates[engine.State]++
	}
	for _, t := range c.Tasks {
		out.TaskStates[t.State]++
	}
	known := false
	for _, node := range nodes {
		known = known || strings.EqualFold(node, c.Node)
	}
	if !known {
		return out, errors.New("runtime node outside fitted scope")
	}
	if len(out.Startups) > 0 {
		copy := out.Startups[0]
		out.Startup = &copy
	}
	later := false
	mismatch := false
	complete := len(c.Engines) > 0
	for _, engine := range c.Engines {
		if engine.Configuration != "observed" || len(engine.Configs) != 1 {
			complete = false
		}
		for _, point := range engine.Configs {
			comparison, transition, e := compareRuntimeConfiguration(cfg, point)
			if e != nil {
				return out, e
			}
			later = later || transition
			mismatch = mismatch || comparison == "mismatch"
			complete = complete && comparison == "startup_scalars_verified"
			state := engine.Configuration
			if state == "" {
				state = "unavailable"
			}
			out.Configurations = append(out.Configurations, RuntimeConfiguration{engine.ID, engine.ParentID, state, point, comparison})
		}
	}
	if len(out.Configurations) > 0 {
		out.Configuration = "incomplete_startup_evidence"
		if complete {
			out.Configuration = "startup_scalars_verified"
		}
		if mismatch {
			out.Configuration = "mismatch"
		}
	} else if len(out.Startups) == 1 {
		comparison, transition, e := compareRuntimeConfiguration(cfg, out.Startups[0])
		if e != nil {
			return out, e
		}
		out.Configuration = comparison
		later = transition
	} else if len(out.Startups) > 1 {
		out.Configuration = "unbound_startup_candidates"
	}
	if later {
		out.Unavailable = append(append([]string(nil), out.Unavailable...), "later_configuration_unproved")
	}
	return out, nil
}

// Compare each local snapshot only at its full recorded height.
func compareRuntimeConfiguration(cfg *types.Config, point runtimeobs.Point) (string, bool, error) {
	if point.Config == nil {
		return "unavailable", false, nil
	}
	measured := point.Config
	h, ok := new(big.Int).SetString(measured.Height, 10)
	if !ok {
		return "unavailable", false, errors.New("invalid runtime startup height")
	}
	height, e := types.HeightFromBig(h)
	if e != nil {
		return "unavailable", false, e
	}
	p := cfg.ConfigAt(height)
	equal := measured.RequestTimeoutMS == strconv.FormatUint(p.RequestTimeoutMs, 10) && measured.BlockPeriodSeconds == strconv.FormatUint(p.BlockPeriodSeconds, 10) && measured.Epoch == strconv.FormatUint(p.EpochLength, 10) && measured.AllowedFutureBlockSeconds == strconv.FormatUint(p.AllowedFutureBlockTime, 10) && measured.MaxRequestTimeoutSeconds == strconv.FormatUint(p.MaxRequestTimeoutSeconds, 10)
	policy := ""
	if p.ProposerPolicy != nil {
		policy = strconv.FormatUint(p.ProposerPolicy.ID, 10)
	}
	equal = equal && measured.ProposerPolicy == policy
	later := measured.Transitions != "0" || measured.SystemContractUpgrades != "0"
	if !equal {
		return "mismatch", later, nil
	}
	return "startup_scalars_verified", later, nil
}
