// Package messages projects public WBFT journals and R-01 frame dumps into
// metadata. Payloads, input bytes, configuration and arbitrary errors never
// cross this package's persistence boundary.
package messages

import "github.com/0xmhha/wbft-analyzer/internal/source/logs"

const Format = "wbft-analyzer-messages/1"
const Normalizer = "wbft-message-normalization/9"

type Clock struct {
	Model  string `json:"model"`
	SkewMS *int64 `json:"skew_ms,omitempty"`
}
type Input struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Node   string `json:"node"` // Address of the recording node, not a display label.
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
}
type Manifest struct {
	Format  string       `json:"format"`
	Name    string       `json:"name"`
	Network logs.Network `json:"network"`
	Clock   Clock        `json:"clock"`
	Inputs  []Input      `json:"inputs"`
}
type File struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type Summary struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Node   string `json:"node"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Files  []File `json:"files"`
}
type Prepared struct {
	Input   Input
	Summary Summary
}

// Record is deliberately closed: no arbitrary field map and no payload bytes.
// Ordinal is the original journal record ordinal or frame file line; Seq is
// the original per-run jseq, which need not be file-ordered in R-01 exports.
// Empty wall/mono values on peer/outcome records remain unknown.
type TimerOperation struct {
	Sequence      string   `json:"sequence"`
	Action        string   `json:"action"`
	Source        string   `json:"source"`
	Output        string   `json:"output"`
	ArmEngine     string   `json:"arm_engine_run"`
	ArmStep       string   `json:"arm_step"`
	ArmOutput     string   `json:"arm_output"`
	EntryMono     string   `json:"arm_entry_mono_ns"`
	Deadline      string   `json:"deadline_mono_ns"`
	TimeoutSHA256 string   `json:"timeout_sha256,omitempty"`
	Timer         string   `json:"timer,omitempty"`
	Generation    string   `json:"generation,omitempty"`
	Height        string   `json:"height,omitempty"`
	Round         string   `json:"round,omitempty"`
	Kinds         []string `json:"cancel_kinds"`
	Decode        string   `json:"decode"`
}
type Record struct {
	IO            *IOInterval     `json:"io,omitempty"`
	Timer         *TimerOperation `json:"timer_operation,omitempty"`
	TimerTrace    string          `json:"timer_trace_version,omitempty"`
	EntryMono     *string         `json:"entry_t_mono_ns,omitempty"`
	EntryWall     string          `json:"entry_t_wall,omitempty"`
	Capture       string          `json:"capture_id,omitempty"`
	ClockSource   string          `json:"clock_source,omitempty"`
	Input         string          `json:"input"`
	File          string          `json:"file"`
	Ordinal       int64           `json:"ordinal"`
	Offset        *int64          `json:"offset,omitempty"`
	Seq           string          `json:"seq"`
	Node          string          `json:"node"`
	Run           string          `json:"run"`
	Type          string          `json:"type"`
	Wall          string          `json:"t_wall,omitempty"`
	Mono          *string         `json:"t_mono_ns,omitempty"`
	Peer          string          `json:"peer,omitempty"`
	PeerStatus    string          `json:"peer_status,omitempty"`
	Dir           string          `json:"dir,omitempty"`
	Phase         string          `json:"phase,omitempty"`
	WireCode      *string         `json:"wire_code,omitempty"`
	Size          *string         `json:"size,omitempty"`
	Key           string          `json:"dedup_key,omitempty"`
	PayloadSHA256 string          `json:"payload_sha256,omitempty"`
	PayloadSource string          `json:"payload_source,omitempty"`
	Decode        string          `json:"decode,omitempty"`
	Height        string          `json:"height,omitempty"`
	Round         string          `json:"round,omitempty"`
	Digest        string          `json:"digest,omitempty"`
	Signer        string          `json:"signer,omitempty"`
	Signature     string          `json:"signature_status,omitempty"`
	Write         string          `json:"write,omitempty"`
	Cause         string          `json:"cause,omitempty"`
	RelayOf       string          `json:"relay_of,omitempty"`
	Of            string          `json:"of,omitempty"`
	Outcome       string          `json:"outcome,omitempty"`
	Offer         string          `json:"offer,omitempty"`
	Check         string          `json:"check,omitempty"`
	Via           string          `json:"via,omitempty"`
	Step          string          `json:"step,omitempty"`
	EngineRun     string          `json:"engine_run,omitempty"`
	Engine        string          `json:"engine,omitempty"`
	Event         string          `json:"event,omitempty"`
	KnownHit      *bool           `json:"known_hit,omitempty"`
	PeerRecentHit *bool           `json:"peer_recent_hit,omitempty"`
	Dropped       string          `json:"dropped,omitempty"`
	GapFirstMono  string          `json:"gap_first_mono_ns,omitempty"`
	GapLastMono   string          `json:"gap_last_mono_ns,omitempty"`
	HeadNumber    string          `json:"head_number,omitempty"`
	HeadHash      string          `json:"head_hash,omitempty"`
	OutDigest     string          `json:"out_digest,omitempty"`
	ConfigDigest  string          `json:"config_digest,omitempty"`
	Improvements  string          `json:"improvements,omitempty"`
}
type Stats struct {
	ClockDiagnostics string `json:"clock_diagnostics"`
	PartialRuns      int64  `json:"partial_runs"`
	Records          int64  `json:"records"`
	Frames           int64  `json:"frames"`
	Decoded          int64  `json:"decoded"`
	Undecoded        int64  `json:"undecoded"`
	UnknownPeers     int64  `json:"unknown_peers"`
	GapRecords       int64  `json:"gap_records"`
	SequenceGaps     int64  `json:"sequence_gaps"`
	ClockRegressions int64  `json:"clock_regressions"`
}
