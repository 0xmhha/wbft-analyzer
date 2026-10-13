// Package reexec drives the public WBFT replay library and versioned helpers.
// It stores only bounded source metadata and output digests, never payloads.
package reexec

import "github.com/0xmhha/wbft-analyzer/internal/source/messages"

const Version = "wbft-closed-reexec/1"
const Protocol = "wbft-replay/1"
const MaxSteps = 100000
const MaxRecords = 1000000

type AnswerSource struct {
	Ordinal int64  `json:"ordinal"`
	File    string `json:"file"`
	Run     string `json:"writer_run"`
	Engine  string `json:"engine_run"`
	Step    string `json:"step"`
	Call    int    `json:"call"`
	Kind    int    `json:"kind"`
	Key     string `json:"key"`
}
type answerContext struct{ writer, engine, head, hash, valset string }
type recordedAnswer struct {
	Source  AnswerSource
	Context answerContext
}

type Step struct {
	ContextAnswers bool           `json:"context_answers,omitempty"`
	AnswerSources  []AnswerSource `json:"answer_sources,omitempty"`
	Approximate    bool           `json:"approximate,omitempty"`
	Warmup         bool           `json:"warmup,omitempty"`
	Capture        string         `json:"capture_id,omitempty"`
	Omitted        bool           `json:"omitted,omitempty"`
	Mono           string         `json:"t_mono_ns,omitempty"`
	Wall           string         `json:"t_wall,omitempty"`
	Offset         *int64         `json:"offset,omitempty"`
	Phase          string         `json:"phase,omitempty"`
	MessageHeight  string         `json:"message_height,omitempty"`
	Round          string         `json:"round,omitempty"`
	MessageDigest  string         `json:"message_digest,omitempty"`
	Peer           string         `json:"input_peer,omitempty"`
	PayloadSHA     string         `json:"payload_sha256,omitempty"`
	ValsetDigest   string         `json:"recorded_valset_digest,omitempty"`

	Ordinal      int64    `json:"ordinal"`
	File         string   `json:"file"`
	Run          string   `json:"writer_run"`
	Engine       string   `json:"engine_run"`
	Number       string   `json:"step"`
	Height       string   `json:"height"`
	Input        string   `json:"input"`
	Recorded     string   `json:"recorded_digest"`
	Replayed     string   `json:"replayed_digest,omitempty"`
	Class        string   `json:"class"`
	Completeness string   `json:"completeness"`
	Issues       []string `json:"issues"`
}

type Height struct {
	Number string   `json:"height"`
	Status string   `json:"status"`
	Issues []string `json:"issues"`
	Steps  int64    `json:"steps"`
}

type Plan struct {
	Answers        map[string]recordedAnswer `json:"-"`
	Contexts       map[int64]answerContext   `json:"-"`
	From, To       uint64                    `json:"-"`
	Input          messages.Prepared         `json:"-"`
	Chain          string                    `json:"-"`
	ChainSHA       string                    `json:"chain_sha256"`
	SourceVersions []string                  `json:"source_versions"`
	Heights        []Height                  `json:"heights"`
	Steps          []Step                    `json:"-"`
	JournalIssue   string                    `json:"journal_issue,omitempty"`
}

type Result struct {
	OmitMissing    bool     `json:"omit_missing_captures,omitempty"`
	AnswerScope    string   `json:"answer_scope,omitempty"`
	WarmupHeights  int      `json:"warmup_heights,omitempty"`
	WarmupSuspect  int64    `json:"warmup_suspect"`
	Warmup         *Warmup  `json:"warmup,omitempty"`
	Mode           string   `json:"mode,omitempty"`
	BinaryVersion  string   `json:"binary_version"`
	HelperSHA      string   `json:"helper_sha256"`
	Version        string   `json:"version"`
	Status         string   `json:"status"`
	HelperVersion  string   `json:"helper_version"`
	VersionStatus  string   `json:"version_status"`
	ChainSHA       string   `json:"chain_sha256"`
	SourceSHA      string   `json:"source_sha256"`
	SourceVersions []string `json:"source_versions"`
	Heights        []Height `json:"heights"`
	Total          int64    `json:"steps"`
	Matches        int64    `json:"matches"`
	Mismatches     int64    `json:"mismatches"`
	NotComparable  int64    `json:"not_comparable"`
	FirstMismatch  *int64   `json:"first_mismatch_ordinal,omitempty"`
	Issue          string   `json:"issue,omitempty"`
}

// Warmup describes the verified original prefix preceding the selected range.
// It is separate from selected-step counters and contains no input payload.
type Warmup struct {
	Suspects          int64  `json:"suspects,omitempty"`
	FromHeight        string `json:"from_height,omitempty"`
	CompareFromHeight string `json:"compare_from_height,omitempty"`
	Policy            string `json:"policy"`
	Status            string `json:"status"`
	Steps             int64  `json:"steps"`
	Matches           int64  `json:"matches"`
	Mismatches        int64  `json:"mismatches"`
	NotComparable     int64  `json:"not_comparable"`
	FirstSource       *int64 `json:"first_source_ordinal,omitempty"`
	LastSource        *int64 `json:"last_source_ordinal,omitempty"`
	FirstDifference   *Step  `json:"first_difference,omitempty"`
}
