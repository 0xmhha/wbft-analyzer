package main

const (
	InputFormat               = "wbft-execution-witness-input/1"
	Protocol                  = "wbft-execution-witness/1"
	OriginPath                = "github.com/stable-net/go-stablenet"
	OriginVersion             = "v0.0.0-20260915070707-740526d0375a"
	OriginSum                 = "h1:M7STXY074tnBtdSP+Z/F3hTptDlwLJOS0pLtWyq5zbs="
	MaxManifestBytes          = 16 << 20
	MaxSourceBytes            = 16 << 20
	MaxReadBytes              = 256 << 20
	MaxProjectionBytes        = 32 << 20
	MaxBlocks                 = 16384
	MaxTransactions           = 100000
	MaxFrames                 = 100000
	MaxLogs                   = 100000
	MaxTransactionLogs        = 4096
	MaxBlockGas        uint64 = 1000000000
	MaxTotalGas        uint64 = 1000000000
)

type FileInput struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type BlockInput struct {
	Index string    `json:"index"`
	File  FileInput `json:"file"`
}
type Manifest struct {
	Format  string       `json:"format"`
	Node    string       `json:"node"`
	Genesis FileInput    `json:"genesis"`
	Blocks  []BlockInput `json:"blocks"`
}
type Digest struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}
type Origin struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
}
type BlockEvidence struct {
	Index           string `json:"index"`
	Hash            string `json:"hash"`
	Parent          string `json:"parent_hash"`
	StateRoot       string `json:"state_root"`
	TransactionRoot string `json:"transaction_root"`
	ReceiptRoot     string `json:"receipt_root"`
	GasUsed         string `json:"gas_used"`
	File            Digest `json:"file"`
}
type Snapshot struct {
	Format       string          `json:"format"`
	Node         string          `json:"node"`
	ChainID      string          `json:"chain_id"`
	GenesisHash  string          `json:"genesis_hash"`
	ConfigSHA256 string          `json:"config_sha256"`
	Manifest     Digest          `json:"manifest"`
	Genesis      Digest          `json:"genesis"`
	Blocks       []BlockEvidence `json:"blocks"`
}
type Frame struct {
	Path             []uint32 `json:"path"`
	Kind             string   `json:"kind"`
	From             string   `json:"from"`
	To               string   `json:"to"`
	Input            Digest   `json:"input"`
	Selector         string   `json:"selector"`
	Return           Digest   `json:"return"`
	Gas              string   `json:"gas"`
	GasUsed          string   `json:"gas_used"`
	Status           string   `json:"status"`
	VMError          string   `json:"vm_error"`
	Effective        bool     `json:"effective"`
	AccountCodeHash  string   `json:"account_code_hash"`
	AccountCodeBytes int      `json:"account_code_bytes"`
	Observation      string   `json:"observation"`
	Authority        string   `json:"authority"`
	AuthorityIndex   string   `json:"authority_config_index"`
	ABIStatus        string   `json:"abi_status"`
	ErrorName        string   `json:"error_name"`
}
type Log struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    Digest   `json:"data"`
}
type Transaction struct {
	Index         string  `json:"index"`
	Ordinal       int     `json:"transaction_index"`
	Hash          string  `json:"hash"`
	BlockHash     string  `json:"block_hash"`
	From          string  `json:"from"`
	To            string  `json:"to"`
	Input         Digest  `json:"input"`
	Selector      string  `json:"selector"`
	GasUsed       string  `json:"gas_used"`
	ReceiptStatus string  `json:"receipt_status"`
	Receipt       Digest  `json:"receipt"`
	Logs          []Log   `json:"logs"`
	Frames        []Frame `json:"frames"`
}
type Report struct {
	Protocol     string        `json:"protocol"`
	Origin       Origin        `json:"origin"`
	Source       Snapshot      `json:"source"`
	Transactions []Transaction `json:"transactions"`
}
