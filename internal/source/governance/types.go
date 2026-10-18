// Package governance reads bounded, metadata-only WBFT governance RPC captures.
// Mirror verification and authority are source claims, not independent verdicts.
package governance

import "encoding/json"

const (
	Format     = "wbft-analyzer-governance/1"
	Normalizer = "wbft-governance-normalization/3"
	MaxBytes   = 32 << 20
	maxRows    = 65536
)

type ProposalKey struct {
	Instance string `json:"instance"`
	ID       string `json:"id"`
}

// Archive contains supplied envelopes. Fetch reconstructs envelopes from client
// results and labels them accordingly; neither form authenticates a remote node.
type Archive struct {
	Format         string        `json:"format"`
	EnvelopeOrigin string        `json:"envelope_origin"`
	From           string        `json:"from"`
	To             string        `json:"to"`
	Instances      []string      `json:"instances"`
	Proposals      []ProposalKey `json:"proposals"`
	Replies        []Reply       `json:"replies"`
}
type Reply struct {
	Method   string          `json:"method"`
	Params   []string        `json:"params"`
	Response json.RawMessage `json:"response"`
}
type Request struct {
	Method string   `json:"method"`
	Params []string `json:"params"`
	Scope  string   `json:"scope"`
}
type Call struct {
	Ordinal   int             `json:"ordinal"`
	Request   Request         `json:"request"`
	Status    string          `json:"status"`
	ErrorCode *int            `json:"error_code,omitempty"`
	SHA256    string          `json:"sha256"`
	Data      json.RawMessage `json:"data"`
}

// Identity deliberately omits build labels, flags, paths and arbitrary strings.
type Identity struct {
	Address     string `json:"address"`
	ChainID     string `json:"chain_id"`
	GenesisHash string `json:"genesis_hash"`
	Head        string `json:"head"`
	HeadHash    string `json:"head_hash"`
}
type Snapshot struct {
	From           string   `json:"from"`
	To             string   `json:"to"`
	EnvelopeOrigin string   `json:"envelope_origin"`
	Atomic         bool     `json:"atomic"`
	Before         Identity `json:"before"`
	After          Identity `json:"after"`
	Calls          []Call   `json:"calls"`
}

// Bytes retains the digest and length, never arbitrary calldata or log data.
type Bytes struct {
	SHA256 string `json:"sha256"`
	Length int    `json:"length"`
}
type Annotation struct {
	Status string `json:"status"`
	Value  *Bytes `json:"value,omitempty"`
}
type Mirror struct {
	Number      string            `json:"number"`
	Hash        string            `json:"hash"`
	Healthy     bool              `json:"healthy"`
	Authority   string            `json:"authority"`
	Modes       map[string]string `json:"modes"`
	Validators  []string          `json:"validators"`
	BLSKeys     []string          `json:"bls_public_keys"`
	GasTip      *string           `json:"gas_tip"`
	Blacklisted []string          `json:"blacklisted"`
	Authorized  []string          `json:"authorized"`
}
type Fault struct {
	Number      string  `json:"number"`
	Kind        string  `json:"kind"`
	Instance    string  `json:"instance"`
	Description Bytes   `json:"description"`
	GapFrom     *string `json:"gap_from,omitempty"`
	GapTo       *string `json:"gap_to,omitempty"`
	BoundsKnown bool    `json:"bounds_known"`
}
type Log struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    Bytes    `json:"data"`
}
type Operation struct {
	BlockHash           *string      `json:"block_hash,omitempty"`
	Number              string       `json:"number"`
	Tx                  uint32       `json:"tx"`
	TxHash              string       `json:"tx_hash"`
	Path                []uint32     `json:"path"`
	From                string       `json:"from"`
	Instance            string       `json:"instance"`
	Input               Bytes        `json:"input"`
	Selector            string       `json:"selector"`
	Call                ContractCall `json:"call"`
	Effective           bool         `json:"effective"`
	View                bool         `json:"view"`
	Result              string       `json:"result"`
	ErrorName           string       `json:"error_name,omitempty"`
	ResultValue         Bytes        `json:"result_value"`
	Logs                []Log        `json:"logs"`
	Verified            bool         `json:"verified"`
	ExecutingProposalID *string      `json:"executing_proposal_id"`
	ValidatorChange     Annotation   `json:"validator_change"`
}
type Proposal struct {
	ID                string `json:"id"`
	ActionType        string `json:"action_type"`
	Proposer          string `json:"proposer"`
	Status            uint8  `json:"status"`
	Approved          uint32 `json:"approved"`
	Rejected          uint32 `json:"rejected"`
	RequiredApprovals uint32 `json:"required_approvals"`
	ExecutionCount    string `json:"execution_count"`
	CallData          Bytes  `json:"call_data"`
}
type ProposalHistory struct {
	Instance string      `json:"instance"`
	ID       string      `json:"id"`
	Proposal *Proposal   `json:"proposal"`
	Ops      []Operation `json:"ops"`
}
type State struct {
	ReportedFields    []string          `json:"reported_fields"`
	Number            string            `json:"number"`
	Instance          string            `json:"instance"`
	Mode              string            `json:"mode"`
	MemberVersion     string            `json:"member_version"`
	Members           []string          `json:"members"`
	Quorum            string            `json:"quorum"`
	ProposalExpiry    string            `json:"proposal_expiry"`
	CurrentProposalID string            `json:"current_proposal_id"`
	MaxProposals      string            `json:"max_proposals"`
	Proposals         []Proposal        `json:"proposals"`
	Validators        []string          `json:"validators,omitempty"`
	Operators         map[string]string `json:"operators,omitempty"`
	GasTip            *string           `json:"gas_tip,omitempty"`
	Blacklist         []string          `json:"blacklist,omitempty"`
	Authorized        []string          `json:"authorized,omitempty"`
	Inexact           bool              `json:"inexact"`
}
type Epoch struct {
	NoKeyReported bool     `json:"no_key_reported"`
	Candidates    []string `json:"candidates"`
	Validators    []string `json:"validators"`
	Added         []string `json:"added"`
	Removed       []string `json:"removed"`
	NoKey         []string `json:"no_key"`
}
type ValidatorChange struct {
	BlockHash          *string     `json:"block_hash,omitempty"`
	Number             string      `json:"number"`
	Validators         []string    `json:"validators"`
	ValidatorsReported bool        `json:"validators_reported"`
	Ops                []Operation `json:"ops"`
	Epoch              *Epoch      `json:"epoch"`
}
