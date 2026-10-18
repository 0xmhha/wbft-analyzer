package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

func digest(raw []byte) Digest {
	sum := sha256.Sum256(raw)
	return Digest{SHA256: hex.EncodeToString(sum[:]), Bytes: len(raw)}
}
func address(text string) bool {
	if len(text) != 42 || !strings.HasPrefix(text, "0x") {
		return false
	}
	_, err := hex.DecodeString(text[2:])
	return err == nil
}
func index(text string) (uint64, bool) {
	n, e := strconv.ParseUint(text, 10, 64)
	return n, e == nil && strconv.FormatUint(n, 10) == text
}
func selector(raw []byte) string {
	if len(raw) < 4 {
		return ""
	}
	return "0x" + hex.EncodeToString(raw[:4])
}

type sourceReader struct {
	ctx       context.Context
	root      *os.Root
	readBytes int
	files     map[string]FileInput
}

func (r *sourceReader) read(input FileInput) ([]byte, Digest, error) {
	if r.ctx.Err() != nil || r.root == nil || input.Path == "" || path.IsAbs(input.Path) || path.Clean(input.Path) != input.Path || input.Path == "." || input.Path == ".." || strings.Contains(input.Path, "\\") || strings.Contains(input.Path, "\x00") || strings.HasPrefix(input.Path, "../") || len(input.SHA256) != 64 {
		return nil, Digest{}, ErrInput
	}
	if raw, err := hex.DecodeString(input.SHA256); err != nil || len(raw) != 32 || input.SHA256 != strings.ToLower(input.SHA256) {
		return nil, Digest{}, ErrInput
	}
	if previous, ok := r.files[input.Path]; ok && previous.SHA256 != input.SHA256 {
		return nil, Digest{}, ErrInput
	}
	parts := strings.Split(input.Path, "/")
	for i := range parts {
		info, err := r.root.Lstat(strings.Join(parts[:i+1], "/"))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, Digest{}, ErrInput
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, Digest{}, ErrInput
		}
		if i == len(parts)-1 && !info.Mode().IsRegular() {
			return nil, Digest{}, ErrInput
		}
	}
	f, err := r.root.Open(input.Path)
	if err != nil {
		return nil, Digest{}, ErrInput
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxSourceBytes || info.Size() > int64(MaxReadBytes-r.readBytes) {
		return nil, Digest{}, ErrInput
	}
	limit := min(MaxSourceBytes, MaxReadBytes-r.readBytes)
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(raw) > MaxSourceBytes || len(raw) > MaxReadBytes-r.readBytes {
		return nil, Digest{}, ErrInput
	}
	r.readBytes += len(raw)
	sum := digest(raw)
	if sum.SHA256 != input.SHA256 {
		return nil, Digest{}, ErrInput
	}
	r.files[input.Path] = input
	return raw, sum, nil
}
func (r *sourceReader) block(input BlockInput) (*types.Block, Digest, error) {
	raw, sum, err := r.read(input.File)
	if err != nil {
		return nil, Digest{}, err
	}
	var block types.Block
	if rlp.DecodeBytes(raw, &block) != nil || block.Number() == nil || !block.Number().IsUint64() || block.Number().String() != input.Index || block.GasLimit() > MaxBlockGas || len(block.Uncles()) != 0 || len(block.Withdrawals()) != 0 || block.UncleHash() != types.EmptyUncleHash {
		return nil, Digest{}, ErrInput
	}
	encoded, err := rlp.EncodeToBytes(&block)
	if err != nil || !bytes.Equal(raw, encoded) {
		return nil, Digest{}, ErrInput
	}
	return &block, sum, nil
}
func loadManifest(ctx context.Context, raw []byte, root *os.Root) (Manifest, *core.Genesis, Snapshot, *sourceReader, error) {
	var m Manifest
	var g core.Genesis
	empty := Snapshot{}
	if exactJSON(raw, MaxManifestBytes, &m) != nil || m.Format != InputFormat || !address(m.Node) || len(m.Blocks) == 0 || len(m.Blocks) > MaxBlocks {
		return m, nil, empty, nil, ErrInput
	}
	for i, b := range m.Blocks {
		n, ok := index(b.Index)
		if !ok || n != uint64(i) {
			return m, nil, empty, nil, ErrInput
		}
	}
	r := &sourceReader{ctx: ctx, root: root, files: map[string]FileInput{}}
	genesis, genesisDigest, err := r.read(m.Genesis)
	if err != nil || exactJSON(genesis, MaxSourceBytes, &g) != nil || g.Config == nil || g.Config.ChainID == nil || g.Config.ChainID.Sign() < 0 || g.Config.ChainID.BitLen() > 256 || !g.Config.AnzeonEnabled() || g.Number != 0 || g.GasLimit > MaxBlockGas || g.IsVerkle() {
		return m, nil, empty, nil, ErrInput
	}
	for _, account := range g.Alloc {
		if len(account.PrivateKey) != 0 {
			return m, nil, empty, nil, ErrInput
		}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(genesis, &fields) != nil || len(fields["config"]) == 0 {
		return m, nil, empty, nil, ErrInput
	}
	cfg := digest(fields["config"])
	s := Snapshot{Format: m.Format, Node: strings.ToLower(m.Node), ChainID: g.Config.ChainID.String(), ConfigSHA256: cfg.SHA256, Manifest: digest(raw), Genesis: genesisDigest, Blocks: []BlockEvidence{}}
	return m, &g, s, r, nil
}
