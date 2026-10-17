// Package reconstruct assesses the original sources needed to reconstruct
// WBFT core inputs from implementation logs and wire captures. Source presence
// alone never establishes processing order or a completed core comparison.
package reconstruct

import (
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

const ManifestFormat = "wbft-reconstruction-input/1"
const Version = "wbft-reconstruction-assessment/1"
const MaxHeights = 10000

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Manifest paths remain local. Only verified hashes and closed source
// coordinates appear in an assessment.
type Manifest struct {
	Format  string       `json:"format"`
	Node    string       `json:"node"`
	Network logs.Network `json:"network"`
	Log     File         `json:"log"`
	Frames  *File        `json:"frames,omitempty"`
	Runtime *File        `json:"runtime,omitempty"`
	Chain   *File        `json:"chain,omitempty"`
}

type Point struct {
	Kind         string `json:"kind"`
	File         string `json:"file"`
	Line         int64  `json:"line,omitempty"`
	BlockIndex   string `json:"block_index,omitempty"`
	Run          string `json:"run,omitempty"`
	Sequence     string `json:"sequence,omitempty"`
	ViewInferred bool   `json:"view_inferred,omitempty"`
}

// Evidence retains a bounded list of examples. Count is the full number of
// original records; examples are never presented as a complete input stream.
type Evidence struct {
	Kind     string  `json:"kind"`
	Count    int64   `json:"count"`
	Examples []Point `json:"examples"`
}

type Height struct {
	Height   string     `json:"height"`
	Status   string     `json:"status"`
	Issues   []string   `json:"issues"`
	Evidence []Evidence `json:"evidence"`
}

type Sources struct {
	LogProfile        string            `json:"log_profile"`
	LogProfileSHA     string            `json:"log_profile_sha256"`
	LogNormalizer     string            `json:"log_normalizer"`
	FrameNormalizer   string            `json:"frame_normalizer,omitempty"`
	RuntimeNormalizer string            `json:"runtime_normalizer,omitempty"`
	LogSHA            string            `json:"log_sha256"`
	LogBytes          int64             `json:"log_bytes"`
	LogStats          logs.Stats        `json:"log_diagnostics"`
	Frames            *messages.Summary `json:"frames,omitempty"`
	FrameStats        *messages.Stats   `json:"frame_diagnostics,omitempty"`
	RuntimeSHA        string            `json:"runtime_sha256,omitempty"`
	ChainSHA          string            `json:"chain_sha256,omitempty"`
}

type Assessment struct {
	Version      string   `json:"version"`
	Phase        string   `json:"phase"`
	Node         string   `json:"node"`
	ChainID      string   `json:"chain_id"`
	GenesisHash  string   `json:"genesis_hash"`
	From         string   `json:"from_height"`
	To           string   `json:"to_height"`
	CoreExecuted bool     `json:"core_executed"`
	Sources      Sources  `json:"sources"`
	Heights      []Height `json:"heights"`
}
