package statewitness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

const (
	InputFormat         = "wbft-execution-state-witness-input/1"
	MaxManifestBytes    = 1 << 20
	MaxSourceBytes      = 16 << 20
	MaxTotalSourceBytes = 256 << 20
	MaxProjectionBytes  = 32 << 20
	MaxWitnessPoints    = 256
)

var ErrSource = errors.New("invalid execution-state witness source")

type FileInput struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type HeaderInput struct {
	Kind string    `json:"kind"`
	File FileInput `json:"file"`
}

type PointInput struct {
	Index    string      `json:"index"`
	Block    HeaderInput `json:"block"`
	Request  FileInput   `json:"request"`
	Response FileInput   `json:"response"`
}

type Manifest struct {
	Format  string       `json:"format"`
	Node    string       `json:"node"`
	Config  FileInput    `json:"config"`
	Genesis HeaderInput  `json:"genesis"`
	Points  []PointInput `json:"points"`
}

type FileEvidence struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type Point struct {
	Index     string         `json:"index"`
	BlockHash string         `json:"block_hash"`
	BlockFile FileEvidence   `json:"block_file"`
	Request   FileEvidence   `json:"request"`
	Response  FileEvidence   `json:"response"`
	State     ValidatorState `json:"state"`
	Epoch     EpochEvidence  `json:"epoch"`
}

// Snapshot has no local paths, raw proof nodes, keys or request payloads.
// Canonical dataset binding and epoch comparisons remain mandatory at store
// ingestion. Node is a declared source label, not an authenticated peer.
type Snapshot struct {
	Format      string       `json:"format"`
	Manifest    FileEvidence `json:"manifest"`
	Node        string       `json:"node"`
	ChainID     string       `json:"chain_id"`
	ConfigSHA   string       `json:"config_sha256"`
	ConfigFile  FileEvidence `json:"config_file"`
	GenesisHash string       `json:"genesis_hash"`
	GenesisFile FileEvidence `json:"genesis_file"`
	Points      []Point      `json:"points"`
}

type Bundle struct{ snapshot Snapshot }

func (b Bundle) Projection() Snapshot {
	out := b.snapshot
	out.Points = append([]Point{}, out.Points...)
	for i := range out.Points {
		s := &out.Points[i].State
		s.Candidates = append([]CandidateKey{}, s.Candidates...)
		s.WithoutKeys = append([]string{}, s.WithoutKeys...)
	}
	return out
}

// Load accepts only relative regular files inside root, verifies their
// checksums twice, and emits no prefix on a later point's failure.
func Load(ctx context.Context, raw []byte, root *os.Root) (Bundle, error) {
	var manifest Manifest
	if root == nil || exactJSON(raw, MaxManifestBytes, &manifest) != nil || manifest.Format != InputFormat ||
		len(manifest.Points) == 0 || len(manifest.Points) > MaxWitnessPoints {
		return Bundle{}, ErrSource
	}
	node, err := fixedHex(manifest.Node, 20)
	if err != nil {
		return Bundle{}, ErrSource
	}
	r := sourceReader{ctx: ctx, root: root, files: map[string]FileInput{}}
	configRaw, configFile, err := r.read(manifest.Config)
	if err != nil {
		return Bundle{}, ErrSource
	}
	cfg, err := ParseAuthorityConfig(configRaw)
	if err != nil {
		return Bundle{}, ErrConfig
	}
	genesis, genesisFile, err := r.header(manifest.Genesis)
	if err != nil || !genesis.Number.IsZero() {
		return Bundle{}, ErrSource
	}
	out := Snapshot{Format: InputFormat, Manifest: digest(raw), Node: "0x" + hex.EncodeToString(node), ChainID: cfg.ChainID, ConfigSHA: cfg.SHA256, ConfigFile: configFile, GenesisHash: codec.BlockHash(genesis).Hex(), GenesisFile: genesisFile, Points: []Point{}}
	seen := map[string]bool{}
	projectionBytes := 0
	for _, input := range manifest.Points {
		if _, valid := decimalIndex(input.Index); !valid || seen[input.Index] {
			return Bundle{}, ErrSource
		}
		seen[input.Index] = true
		header, blockFile, err := r.header(input.Block)
		if err != nil || header.Number.String() != input.Index {
			return Bundle{}, ErrSource
		}
		authority, err := cfg.ContractAt(header.Number.Big())
		if err != nil {
			return Bundle{}, ErrConfig
		}
		request, requestFile, err := r.read(input.Request)
		if err != nil {
			return Bundle{}, ErrSource
		}
		response, responseFile, err := r.read(input.Response)
		if err != nil {
			return Bundle{}, ErrSource
		}
		account, err := VerifyRPC(request, response, header.Number.Big(), authority, header.Root)
		if err != nil {
			return Bundle{}, err
		}
		state, err := DecodeValidatorState(account)
		if err != nil {
			return Bundle{}, err
		}
		extra, err := codec.DecodeExtra(header)
		if err != nil {
			return Bundle{}, ErrSource
		}
		point := Point{Index: input.Index, BlockHash: codec.BlockHash(header).Hex(), BlockFile: blockFile, Request: requestFile, Response: responseFile, State: state, Epoch: epochEvidence(extra.EpochInfo, state)}
		encoded, err := json.Marshal(point)
		if err != nil || len(encoded) > MaxProjectionBytes-projectionBytes {
			return Bundle{}, ErrSource
		}
		projectionBytes += len(encoded)
		out.Points = append(out.Points, point)
	}
	for _, input := range r.files {
		if _, _, err := r.read(input); err != nil {
			return Bundle{}, ErrSource
		}
	}
	encoded, err := json.Marshal(out)
	if err != nil || len(encoded) > MaxProjectionBytes {
		return Bundle{}, ErrSource
	}
	return Bundle{snapshot: out}, nil
}

type sourceReader struct {
	ctx   context.Context
	root  *os.Root
	total int
	files map[string]FileInput
}

func (r *sourceReader) read(input FileInput) ([]byte, FileEvidence, error) {
	if r.ctx.Err() != nil || !fs.ValidPath(input.Path) || len(input.SHA256) != 64 || strings.ToLower(input.SHA256) != input.SHA256 {
		return nil, FileEvidence{}, ErrSource
	}
	if _, err := hex.DecodeString(input.SHA256); err != nil {
		return nil, FileEvidence{}, ErrSource
	}
	if prior, ok := r.files[input.Path]; ok && prior != input {
		return nil, FileEvidence{}, ErrSource
	}
	// Reject symbolic links within root as well as root escapes. The root API
	// additionally fences any race that attempts to traverse outside root.
	name := ""
	for _, component := range strings.Split(input.Path, "/") {
		name = path.Join(name, component)
		info, err := r.root.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, FileEvidence{}, ErrSource
		}
		if name == input.Path && !info.Mode().IsRegular() {
			return nil, FileEvidence{}, ErrSource
		}
	}
	file, err := r.root.Open(input.Path)
	if err != nil {
		return nil, FileEvidence{}, ErrSource
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxSourceBytes || info.Size() < 1 {
		return nil, FileEvidence{}, ErrSource
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxSourceBytes+1))
	if err != nil || r.ctx.Err() != nil || len(data) > MaxSourceBytes || len(data) > MaxTotalSourceBytes-r.total {
		return nil, FileEvidence{}, ErrSource
	}
	r.total += len(data)
	evidence := digest(data)
	if evidence.SHA256 != input.SHA256 {
		return nil, FileEvidence{}, ErrSource
	}
	r.files[input.Path] = input
	return data, evidence, nil
}

func (r *sourceReader) header(input HeaderInput) (*types.Header, FileEvidence, error) {
	raw, evidence, err := r.read(input.File)
	if err != nil {
		return nil, FileEvidence{}, ErrSource
	}
	var header *types.Header
	var encoded []byte
	switch input.Kind {
	case "header_rlp":
		header, err = codec.DecodeHeader(raw)
		if err == nil {
			encoded, err = codec.EncodeHeader(header)
		}
	case "block_rlp":
		var block *types.Block
		block, err = codec.DecodeBlock(raw)
		if err == nil {
			header = block.Header
			encoded, err = codec.EncodeBlock(block)
		}
	default:
		return nil, FileEvidence{}, ErrSource
	}
	if err != nil || header == nil || !bytes.Equal(raw, encoded) {
		return nil, FileEvidence{}, ErrSource
	}
	return header, evidence, nil
}

func digest(raw []byte) FileEvidence {
	sum := sha256.Sum256(raw)
	return FileEvidence{SHA256: hex.EncodeToString(sum[:]), Bytes: len(raw)}
}
