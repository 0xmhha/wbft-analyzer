package main

const TransitionProtocol = "wbft-governance-transitions/1"
const registryLayout = "wbft-validator-registry/1"

type ContractStorage struct {
	Address     string `json:"address"`
	CodeHash    string `json:"code_hash"`
	StorageRoot string `json:"storage_root"`
	Exists      bool   `json:"exists"`
}

type RegistryCandidate struct {
	Address  string `json:"address"`
	Operator string `json:"operator"`
	Key      Digest `json:"key"`
}

type RegistryState struct {
	Layout      string              `json:"layout"`
	Address     string              `json:"address"`
	CodeHash    string              `json:"code_hash"`
	StorageRoot string              `json:"storage_root"`
	Candidates  []RegistryCandidate `json:"candidates"`
	WithoutKeys []string            `json:"without_keys"`
}

type RegistryRead struct {
	Status string         `json:"status"`
	Reason string         `json:"reason"`
	State  *RegistryState `json:"state"`
}

type ProposalState struct {
	ID                string `json:"id"`
	Status            string `json:"status"`
	Action            string `json:"action"`
	CallData          Digest `json:"call_data"`
	MemberVersion     string `json:"member_version"`
	CreatedAt         string `json:"created_at"`
	ExecutedAt        string `json:"executed_at"`
	Proposer          string `json:"proposer"`
	RequiredApprovals uint32 `json:"required_approvals"`
	Approved          uint32 `json:"approved"`
	Rejected          uint32 `json:"rejected"`
	ExecutionCount    string `json:"execution_count"`
}

type StorageWrite struct {
	Address       string              `json:"address"`
	SlotSHA256    string              `json:"slot_sha256"`
	Before        Digest              `json:"before"`
	After         Digest              `json:"after"`
	OwnerCodeHash string              `json:"owner_code_hash"`
	Frame         int                 `json:"frame"`
	Path          []uint32            `json:"path"`
	Reverted      bool                `json:"reverted"`
	Instruction   *StorageInstruction `json:"instruction"`
}

type StorageInstruction struct {
	PC            string `json:"pc"`
	CodeReference string `json:"code_reference"`
	CodeHash      string `json:"code_hash"`
}

type RegistryEffect struct {
	Kind      string             `json:"kind"`
	Candidate string             `json:"candidate"`
	Before    *RegistryCandidate `json:"before"`
	After     *RegistryCandidate `json:"after"`
}

type TransactionTransition struct {
	Index          string            `json:"index"`
	Ordinal        int               `json:"transaction_index"`
	Hash           string            `json:"hash"`
	BlockHash      string            `json:"block_hash"`
	Status         string            `json:"status"`
	Reason         string            `json:"reason"`
	Method         string            `json:"method"`
	AccountsBefore []ContractStorage `json:"accounts_before"`
	AccountsAfter  []ContractStorage `json:"accounts_after"`
	Writes         []StorageWrite    `json:"writes"`
	RegistryBefore RegistryRead      `json:"registry_before"`
	RegistryAfter  RegistryRead      `json:"registry_after"`
	ProposalBefore *ProposalState    `json:"proposal_before"`
	ProposalAfter  *ProposalState    `json:"proposal_after"`
	Effects        []RegistryEffect  `json:"effects"`
	CauseStatus    string            `json:"cause_status"`
}

type BlockTransition struct {
	Index              string            `json:"index"`
	Genesis            bool              `json:"genesis"`
	BeforeSystem       []ContractStorage `json:"before_system"`
	BeforeTransactions []ContractStorage `json:"before_transactions"`
	AfterTransactions  []ContractStorage `json:"after_transactions"`
	Finalized          []ContractStorage `json:"finalized"`
	EpochRegistry      *RegistryRead     `json:"epoch_registry"`
}

type TransitionReport struct {
	Protocol     string                  `json:"protocol"`
	Execution    Report                  `json:"execution"`
	Blocks       []BlockTransition       `json:"blocks"`
	Transactions []TransactionTransition `json:"transactions"`
}
