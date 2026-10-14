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
type RuntimeBinding struct {
	Source                 Input             `json:"source"`
	Run                    string            `json:"run"`
	Startup                *runtimeobs.Point `json:"startup"`
	Configuration          string            `json:"configuration"`
	CaptureComplete        bool              `json:"capture_complete"`
	Calls                  []runtimeobs.Call `json:"-"`
	CallCount              int               `json:"call_count"`
	Unavailable            []string          `json:"unavailable"`
	ExecutionModelComplete bool              `json:"execution_model_complete"`
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
	out := RuntimeBinding{Source: in.Source, Run: c.Run, Configuration: "unavailable", CaptureComplete: c.Complete, Calls: c.Calls, CallCount: len(c.Calls), Unavailable: c.Unavailable}
	if cfg == nil || in.Source.Node != c.Node || in.Source.SHA256 != c.SourceSHA {
		return out, errors.New("invalid runtime binding")
	}
	known := false
	for _, node := range nodes {
		known = known || strings.EqualFold(node, c.Node)
	}
	if !known {
		return out, errors.New("runtime node outside fitted scope")
	}
	for _, p := range c.Points {
		if p.Type == "runtime_start" {
			copy := p
			out.Startup = &copy
			break
		}
	}
	if out.Startup == nil || out.Startup.Config == nil {
		return out, nil
	}
	measured := out.Startup.Config
	h, ok := new(big.Int).SetString(measured.Height, 10)
	if !ok {
		return out, errors.New("invalid runtime startup height")
	}
	height, e := types.HeightFromBig(h)
	if e != nil {
		return out, e
	}
	p := cfg.ConfigAt(height)
	equal := measured.RequestTimeoutMS == strconv.FormatUint(p.RequestTimeoutMs, 10) && measured.BlockPeriodSeconds == strconv.FormatUint(p.BlockPeriodSeconds, 10) && measured.Epoch == strconv.FormatUint(p.EpochLength, 10) && measured.AllowedFutureBlockSeconds == strconv.FormatUint(p.AllowedFutureBlockTime, 10) && measured.MaxRequestTimeoutSeconds == strconv.FormatUint(p.MaxRequestTimeoutSeconds, 10)
	policy := ""
	if p.ProposerPolicy != nil {
		policy = strconv.FormatUint(p.ProposerPolicy.ID, 10)
	}
	equal = equal && measured.ProposerPolicy == policy
	if !equal {
		out.Configuration = "mismatch"
		return out, nil
	}
	out.Configuration = "startup_scalars_verified"
	if measured.Transitions != "0" || measured.SystemContractUpgrades != "0" {
		out.Unavailable = append(append([]string(nil), out.Unavailable...), "later_configuration_unproved")
	}
	return out, nil
}
