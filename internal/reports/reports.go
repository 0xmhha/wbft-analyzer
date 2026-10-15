// Package reports reads wbft-inspector reports (wbft-inspector-report/1)
// and admits only those of the public inspector build for the public
// specification (design.md 3.4 and 9).
package reports

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/0xmhha/wbft-analyzer/internal/privacy"
)

// Schema is the report schema this package reads.
const Schema = "wbft-inspector-report/1"

// Report is the part of an inspector report the analyzer stores.
type Report struct {
	// ID is the sha256 of the report file: the same file loaded twice is
	// the same report.
	ID string `json:"-"`

	Schema       string            `json:"schema"`
	Run          Run               `json:"run"`
	Summary      json.RawMessage   `json:"summary"`
	Results      []Result          `json:"results"`
	Observations []Observation     `json:"observations"`
	Errors       []json.RawMessage `json:"errors"`
}

// Run is the run section of a report.
type Run struct {
	Inputs     []Input         `json:"inputs,omitempty"`
	ID         string          `json:"id"`
	StartedAt  string          `json:"started_at"`
	FinishedAt string          `json:"finished_at"`
	Inspector  Inspector       `json:"inspector"`
	Spec       Spec            `json:"spec"`
	Network    json.RawMessage `json:"network,omitempty"`
	Range      json.RawMessage `json:"range,omitempty"`
}

// Input is a source identity; paths and launch metadata are deliberately absent.
type Input struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Node    string `json:"node,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Profile string `json:"profile,omitempty"`
}

// Inspector is the build that wrote a report.
type Inspector struct {
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	Build         string `json:"build"`
	CatalogSHA256 string `json:"catalog_sha256"`
}

// Spec is the specification a report was decided against.
type Spec struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
}

// Result is the verdict of one requirement.
type Result struct {
	Requirement string          `json:"requirement"`
	Node        string          `json:"node,omitempty"`
	Verdict     string          `json:"verdict"`
	Coverage    json.RawMessage `json:"coverage"`
}

// Observation is a finding that is not a verdict.
type Observation struct {
	Evidence     []Evidence `json:"evidence"`
	ID           string     `json:"id"`
	Kind         string     `json:"kind"`
	Imp          []string   `json:"imp"`
	Requirements []string   `json:"requirements,omitempty"`
	Node         string     `json:"node,omitempty"`
	Count        int64      `json:"count"`
	First        string     `json:"first,omitempty"`
	Last         string     `json:"last,omitempty"`
}

// Evidence is a source pointer. Payload, value and execution state are not stored.
type Evidence struct {
	Address string `json:"address,omitempty"`
	Kind    string `json:"kind"`
	Input   string `json:"input,omitempty"`
	Node    string `json:"node,omitempty"`
	Number  string `json:"number,omitempty"`
	Hash    string `json:"hash,omitempty"`
	Field   string `json:"field,omitempty"`
	Line    int64  `json:"line,omitempty"`
}

// ErrFormat is a file that is not a report of the supported schema.
var ErrFormat = errors.New("reports: not a wbft-inspector-report/1 report")

// ErrRefused is a report that the public build does not accept. The error
// names the check that refused it but no requirement ID: the IDs a refused
// report carries are not recorded (design.md 9, 3).
var ErrRefused = errors.New("reports: refused")

// Parse reads a report file: the schema name and the fields the analyzer
// relies on must be there. It does not apply the public-build checks
// (Admit).
func Parse(raw []byte) (*Report, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	var r Report
	if err := d.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if d.More() {
		return nil, fmt.Errorf("%w: data after the report", ErrFormat)
	}
	switch {
	case r.Schema != Schema:
		return nil, fmt.Errorf("%w: schema %q", ErrFormat, r.Schema)
	case r.Run.ID == "" || r.Run.Inspector.Build == "" || r.Run.Inspector.CatalogSHA256 == "" || r.Run.Spec.Commit == "":
		return nil, fmt.Errorf("%w: run.id, run.inspector.build, run.inspector.catalog_sha256 and run.spec.commit are required", ErrFormat)
	case r.Results == nil || r.Observations == nil || r.Summary == nil || r.Errors == nil:
		return nil, fmt.Errorf("%w: summary, results, observations and errors are required", ErrFormat)
	}
	for i, x := range r.Results {
		if x.Requirement == "" || x.Verdict == "" {
			return nil, fmt.Errorf("%w: results[%d] lacks requirement or verdict", ErrFormat, i)
		}
	}
	for i, o := range r.Observations {
		if o.ID == "" || o.Kind == "" {
			return nil, fmt.Errorf("%w: observations[%d] lacks id or kind", ErrFormat, i)
		}
	}
	seenInputs := map[string]bool{}
	for _, in := range r.Run.Inputs {
		if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`).MatchString(in.ID) || seenInputs[in.ID] || in.SHA256 != "" && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(in.SHA256) {
			return nil, fmt.Errorf("%w: invalid or duplicate source identity", ErrFormat)
		}
		if !map[string]bool{"rpc": true, "log": true, "frames": true, "events": true, "genesis": true, "vectors": true, "impl": true, "cache": true}[in.Kind] {
			return nil, fmt.Errorf("%w: unknown source kind", ErrFormat)
		}
		if in.Profile != "" && !regexp.MustCompile(`^(gstable@740526d03|wbft@[0-9a-f]{12})$`).MatchString(in.Profile) {
			return nil, fmt.Errorf("%w: unknown source profile", ErrFormat)
		}
		seenInputs[in.ID] = true
	}
	sum := sha256.Sum256(raw)
	r.ID = hex.EncodeToString(sum[:])
	return &r, nil
}

// Admit checks an exact inspector build, its complete requirement set and its
// complete catalog hash. Extensions cannot change the public profile. Failure
// refuses the whole report without naming unknown identifiers.
func Admit(r *Report) error {
	if err := privacy.Check(); err != nil {
		return err
	}
	if !privacy.TrustedBuild(r.Run.Inspector.Build) {
		return fmt.Errorf("%w: inspector build is not public or registered", ErrRefused)
	}
	for _, x := range r.Results {
		if !privacy.TrustedRequirement(r.Run.Inspector.Build, x.Requirement) {
			return fmt.Errorf("%w: a result names a requirement outside the trusted specification", ErrRefused)
		}
	}
	for _, o := range r.Observations {
		for _, id := range o.Requirements {
			if !privacy.TrustedRequirement(r.Run.Inspector.Build, id) {
				return fmt.Errorf("%w: an observation names a requirement outside the trusted specification", ErrRefused)
			}
		}
	}
	if !privacy.TrustedCatalog(r.Run.Inspector.Build, r.Run.Inspector.CatalogSHA256) {
		return fmt.Errorf("%w: the catalog hash is not trusted for this inspector build", ErrRefused)
	}
	return nil
}
