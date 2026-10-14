package runtimeobs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
)

const Normalizer = "wbft-runtime-observations/4"

// Point is a closed, precision-safe projection of an original line. Numeric
// values remain decimal strings in persistence and browser API responses.
type Point struct {
	ParentID      string   `json:"parent_id,omitempty"`
	Stage         string   `json:"stage,omitempty"`
	Line          int      `json:"line"`
	Type          string   `json:"type"`
	Seq           string   `json:"seq"`
	Wall          string   `json:"t_wall"`
	Mono          string   `json:"t_mono_ns"`
	ID            string   `json:"id,omitempty"`
	Operation     string   `json:"operation,omitempty"`
	Height        string   `json:"height,omitempty"`
	Hash          string   `json:"hash,omitempty"`
	Count         string   `json:"count,omitempty"`
	Result        string   `json:"result,omitempty"`
	Index         string   `json:"index,omitempty"`
	EngineStopped *bool    `json:"engine_stopped,omitempty"`
	Dropped       string   `json:"dropped,omitempty"`
	Config        *Startup `json:"config,omitempty"`
}
type Startup struct {
	Address                   string `json:"address"`
	Height                    string `json:"height"`
	RequestTimeoutMS          string `json:"request_timeout_ms"`
	BlockPeriodSeconds        string `json:"block_period_seconds"`
	Epoch                     string `json:"epoch"`
	AllowedFutureBlockSeconds string `json:"allowed_future_block_seconds"`
	MaxRequestTimeoutSeconds  string `json:"max_request_timeout_seconds"`
	ProposerPolicy            string `json:"proposer_policy"`
	Transitions               string `json:"transitions"`
	SystemContractUpgrades    string `json:"system_contract_upgrades"`
}
type Capture struct {
	Startups                           []Point          `json:"startups"`
	Engines                            []EngineEvidence `json:"engines"`
	Tasks                              []TaskEvidence   `json:"tasks"`
	Normalizer                         string           `json:"normalizer"`
	SourceSHA                          string           `json:"source_sha256"`
	Node                               string           `json:"node"`
	Run                                string           `json:"run"`
	Complete                           bool             `json:"capture_complete"`
	SequenceGaps                       string           `json:"sequence_gaps"`
	Unavailable                        []string         `json:"unavailable"`
	Calls                              []Call           `json:"calls"`
	Points                             []Point          `json:"points"`
	RuntimeModelComplete               bool             `json:"runtime_model_complete"`
	DeliveryCoverageProven             bool             `json:"delivery_coverage_proven"`
	ApplicationRequestCompletionProven bool             `json:"application_request_completion_proven"`
}

func Load(path string) (Capture, error) {
	f, e := os.Open(path)
	if e != nil {
		return Capture{}, errors.New("runtime observation input unavailable")
	}
	defer f.Close()
	return FromReader(f)
}

// FromReader normalizes only the supplied bytes and binds their exact digest.
func FromReader(reader io.Reader) (Capture, error) {
	h := sha256.New()
	r, e := Read(io.TeeReader(reader, h))
	if e != nil {
		return Capture{}, e
	}
	out := Capture{Normalizer: Normalizer, SourceSHA: hex.EncodeToString(h.Sum(nil)), Node: r.Node, Run: r.Run, Complete: r.CaptureComplete, SequenceGaps: r.SequenceGaps, Unavailable: r.Unavailable, Calls: r.Calls, Points: []Point{}, Tasks: []TaskEvidence{}, Engines: []EngineEvidence{}, Startups: []Point{}}
	number := func(n uint64) string { return strconv.FormatUint(n, 10) }
	for _, x := range r.Records {
		p := Point{Line: x.Line, Type: x.Type, Seq: number(x.Seq), Wall: x.Wall, Mono: number(x.Mono), Height: x.Height, Hash: x.Hash, Operation: x.Operation, Result: x.Result, Stage: x.Stage, EngineStopped: x.EngineStopped}
		switch x.Type {
		case "operation_start":
			p.ID = number(x.ID)
			p.Count = number(x.Count)
		case "engine_created", "engine_stage", "engine_config":
			p.ID = number(x.ID)
			p.ParentID = number(x.ParentID)
		case "operation_stage":
			p.ID = number(x.ID)
		case "operation_end":
			p.ID = number(x.ID)
			p.Index = number(x.Index)
		case "capture_end":
			p.Dropped = number(x.Dropped)
		}
		if c := x.Config; c != nil {
			p.Config = &Startup{c.Address, c.Height, c.RequestTimeoutMS, c.BlockPeriodSeconds, c.Epoch, c.AllowedFutureBlockSeconds, c.MaxRequestTimeoutSeconds, c.ProposerPolicy, number(c.Transitions), number(c.SystemContractUpgrades)}
		}
		out.Points = append(out.Points, p)
		if p.Type == "runtime_start" {
			out.Startups = append(out.Startups, p)
		}
	}
	for _, task := range r.Tasks {
		out.Tasks = append(out.Tasks, projectEvidence(task, out.Points, out.Complete))
	}
	for _, engine := range r.Engines {
		out.Engines = append(out.Engines, projectEngineEvidence(engine, out.Points))
	}
	return out, nil
}

// Validate refuses inconsistent projections before persistence. The complete
// raw file hash remains provenance; normalized JSON is never claimed as bytes.
func (c Capture) Validate() error {
	if c.Normalizer != Normalizer || !address.MatchString(c.Node) || !identity.MatchString(c.Run) || len(c.SourceSHA) != 64 || len(c.Points) > MaxRecords || len(c.Calls) > MaxRecords || len(c.Tasks) > MaxRecords || len(c.Engines) > MaxRecords || len(c.Startups) > MaxRecords || c.RuntimeModelComplete || c.DeliveryCoverageProven || c.ApplicationRequestCompletionProven {
		return errors.New("invalid runtime observation projection")
	}
	if _, e := hex.DecodeString(c.SourceSHA); e != nil {
		return errors.New("invalid runtime source hash")
	}
	if c.Complete && len(c.Unavailable) > 0 {
		return errors.New("inconsistent runtime completeness")
	}
	raw, e := json.Marshal(c)
	if e != nil || len(raw) > 128<<20 {
		return errors.New("runtime projection too large")
	}
	return nil
}

// StartupCandidates derives the full historical list from original points,
// including older stored captures that predate the explicit list field.
func StartupCandidates(c Capture) []Point {
	out := []Point{}
	for _, point := range c.Points {
		if point.Type == "runtime_start" {
			out = append(out, point)
		}
	}
	return out
}
