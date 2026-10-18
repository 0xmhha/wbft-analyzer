// Package inputobs reads actual processing-boundary observations made by an
// instrumented WBFT process. They are not native message-journal steps.
package inputobs

const Format = "wbft-input-observations/1"
const Normalizer = "wbft-input-observation-normalization/1"
const MaxInputs = 100000
const MaxBytes = 128 << 20

type View struct {
	Height       string      `json:"height,omitempty"`
	Round        string      `json:"round,omitempty"`
	State        string      `json:"state,omitempty"`
	Proposer     string      `json:"proposer,omitempty"`
	ValsetDigest string      `json:"valset_digest,omitempty"`
	Config       *Parameters `json:"config,omitempty"`
}

type Parameters struct {
	RequestTimeoutMS          string `json:"request_timeout_ms"`
	BlockPeriodSeconds        string `json:"block_period_seconds"`
	Epoch                     string `json:"epoch"`
	MaxRequestTimeoutSeconds  string `json:"max_request_timeout_seconds"`
	AllowedFutureBlockSeconds string `json:"allowed_future_block_seconds"`
	ProposerPolicy            string `json:"proposer_policy"`
}

type Input struct {
	Answers          []Answer `json:"answers,omitempty"`
	Ordinal          string   `json:"ordinal"`
	Instance         string   `json:"instance"`
	Kind             string   `json:"kind"`
	BeginLine        int64    `json:"begin_line"`
	EndLine          int64    `json:"end_line,omitempty"`
	BeginWall        string   `json:"begin_wall"`
	EndWall          string   `json:"end_wall,omitempty"`
	BeginMono        string   `json:"begin_mono_ns"`
	EndMono          string   `json:"end_mono_ns,omitempty"`
	Code             string   `json:"code,omitempty"`
	Peer             string   `json:"peer,omitempty"`
	PeerKnown        *bool    `json:"peer_known,omitempty"`
	PayloadAvailable *bool    `json:"payload_available,omitempty"`
	PayloadSHA       string   `json:"payload_sha256,omitempty"`
	NilRequest       bool     `json:"nil_request,omitempty"`
	TargetRound      string   `json:"target_round,omitempty"`
	Before           View     `json:"before"`
	After            View     `json:"after"`
	Payload          []byte   `json:"-"`
}

// Answer is an application result observed inside one processing boundary.
// Capture completeness does not establish that every replay call is bound.
type Answer struct {
	Method           string `json:"method"`
	Line             int64  `json:"line"`
	Wall             string `json:"wall"`
	Mono             string `json:"mono_ns"`
	Outcome          string `json:"outcome,omitempty"`
	DurationNS       string `json:"duration_ns,omitempty"`
	ArgumentSHA      string `json:"argument_sha256,omitempty"`
	SubjectHash      string `json:"subject_hash,omitempty"`
	HeadProposer     string `json:"head_proposer,omitempty"`
	Bad              *bool  `json:"is_bad,omitempty"`
	PayloadAvailable *bool  `json:"payload_available,omitempty"`
	PayloadSHA       string `json:"payload_sha256,omitempty"`
	Payload          []byte `json:"-"`
}

type Capture struct {
	Format       string   `json:"format"`
	Normalizer   string   `json:"normalizer"`
	Node         string   `json:"node"`
	Run          string   `json:"run"`
	FrameRun     string   `json:"frame_run"`
	GenesisSHA   string   `json:"genesis_sha256"`
	BinarySHA    string   `json:"binary_sha256"`
	SourceCommit string   `json:"source_commit"`
	SHA256       string   `json:"source_sha256"`
	Bytes        int64    `json:"bytes"`
	Complete     bool     `json:"capture_complete"`
	Unavailable  []string `json:"unavailable"`
	Inputs       []Input  `json:"inputs"`
}
