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
const MaxProcessingRecords = 100000
const ProcessingVersion = "wbft-processing-witnesses/1"

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Manifest paths remain local. Only verified hashes and closed source
// coordinates appear in an assessment.
type Manifest struct {
	Scopes  []RunScope   `json:"processing_scopes,omitempty"`
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

// RunScope declares a fixed same-execution interval. Exact own-message
// content corroborates this declaration; it does not establish a complete
// core input order, receive-to-handle delivery, timer or application history.
type RunScope struct {
	LogRun   string `json:"log_run"`
	FrameRun string `json:"frame_run"`
	From     string `json:"from_t"`
	To       string `json:"to_t"`
}
type ProcessingScope struct {
	From             string          `json:"from_t"`
	To               string          `json:"to_t"`
	LogRun           string          `json:"log_run"`
	FrameRun         string          `json:"frame_run"`
	Status           string          `json:"status"`
	DistinctPayloads int64           `json:"distinct_payloads"`
	Anchors          []ContentAnchor `json:"anchors"`
}
type ContentAnchor struct {
	SHA256 string `json:"payload_sha256"`
	Log    Point  `json:"log"`
	Frame  Point  `json:"frame"`
}
type ProcessingCandidate struct {
	Source        Point  `json:"source"`
	Peer          string `json:"peer"`
	PayloadSHA256 string `json:"payload_sha256"`
	Digest        string `json:"digest"`
}
type ProcessingWitness struct {
	DeclaredDigest          string                `json:"declared_digest,omitempty"`
	Phase                   string                `json:"phase"`
	Height                  string                `json:"height"`
	Round                   string                `json:"round"`
	Signer                  string                `json:"signer,omitempty"`
	Handler                 Point                 `json:"handler"`
	Status                  string                `json:"status"`
	SourceUses              int64                 `json:"source_uses"`
	CandidateCount          int64                 `json:"candidate_count"`
	Candidates              []ProcessingCandidate `json:"candidates"`
	CandidatesTruncated     bool                  `json:"candidates_truncated"`
	ApplicationVerification string                `json:"application_verification"`
	Accepted                *Point                `json:"accepted,omitempty"`
	CoreInputReady          bool                  `json:"core_input_ready"`
}

type Height struct {
	Processing []ProcessingWitness `json:"processing_witnesses,omitempty"`
	Height     string              `json:"height"`
	Status     string              `json:"status"`
	Issues     []string            `json:"issues"`
	Evidence   []Evidence          `json:"evidence"`
}

type Sources struct {
	ProcessingInvalidPayloads int64             `json:"incomplete_logged_payloads"`
	ProcessingUnlocated       int64             `json:"unlocated_processing_handlers"`
	ProcessingVersion         string            `json:"processing_version"`
	ProcessingScopes          []ProcessingScope `json:"processing_scopes"`
	LogProfile                string            `json:"log_profile"`
	LogProfileSHA             string            `json:"log_profile_sha256"`
	LogNormalizer             string            `json:"log_normalizer"`
	FrameNormalizer           string            `json:"frame_normalizer,omitempty"`
	RuntimeNormalizer         string            `json:"runtime_normalizer,omitempty"`
	LogSHA                    string            `json:"log_sha256"`
	LogBytes                  int64             `json:"log_bytes"`
	LogStats                  logs.Stats        `json:"log_diagnostics"`
	Frames                    *messages.Summary `json:"frames,omitempty"`
	FrameStats                *messages.Stats   `json:"frame_diagnostics,omitempty"`
	RuntimeSHA                string            `json:"runtime_sha256,omitempty"`
	ChainSHA                  string            `json:"chain_sha256,omitempty"`
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
