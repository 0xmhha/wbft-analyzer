package executionwitness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/keccak"
)

var ErrSource = errors.New("execution witness originals or implementation could not be verified")

type Verifier struct {
	SHA256 string `json:"sha256"`
	Origin Origin `json:"origin"`
}
type Projection struct {
	Report   Report   `json:"report"`
	Verifier Verifier `json:"verifier"`
}

// Bundle can only be constructed by executing a trusted, fingerprinted helper
// against immutable original sources. Deserializing a report cannot create it.
type Bundle struct{ value Projection }

// A verified bundle has no external JSON input representation.
func (*Bundle) UnmarshalJSON([]byte) error { return ErrSource }

func (b Bundle) Projection() Projection {
	raw, _ := json.Marshal(b.value)
	var out Projection
	_ = json.Unmarshal(raw, &out)
	return out
}

func exactJSON(raw []byte, limit int, dst any) error {
	if !utf8.Valid(raw) || jsonmeta.Decode(raw, limit, true, dst) != nil || !exactFields(raw, reflect.TypeOf(dst).Elem()) {
		return ErrSource
	}
	return nil
}
func exactFields(raw json.RawMessage, t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil || m == nil {
			return false
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
		for key, value := range m {
			field, ok := fields[key]
			if !ok || !exactFields(value, field) {
				return false
			}
		}
	case reflect.Slice:
		var list []json.RawMessage
		if json.Unmarshal(raw, &list) != nil {
			return false
		}
		for _, value := range list {
			if !exactFields(value, t.Elem()) {
				return false
			}
		}
	}
	return true
}
func digest(raw []byte) Digest {
	sum := sha256.Sum256(raw)
	return Digest{SHA256: hex.EncodeToString(sum[:]), Bytes: len(raw)}
}
func hash(text string, size int) bool {
	if len(text) != size*2 || text != strings.ToLower(text) {
		return false
	}
	_, err := hex.DecodeString(text)
	return err == nil
}
func wireHex(text string, size int) bool {
	return strings.HasPrefix(text, "0x") && hash(text[2:], size)
}
func number(text string) (uint64, bool) {
	n, err := strconv.ParseUint(text, 10, 64)
	return n, err == nil && strconv.FormatUint(n, 10) == text
}

type originalFile struct {
	input  FileInput
	digest Digest
}
type expectedTransaction struct {
	index     string
	ordinal   int
	hash      string
	blockHash string
}
type snapshot struct {
	manifest     Manifest
	source       Snapshot
	files        map[string]originalFile
	transactions []expectedTransaction
	readBytes    int
}

func readOriginal(ctx context.Context, root *os.Root, input FileInput, remaining int) ([]byte, error) {
	if ctx.Err() != nil || root == nil || input.Path == "" || input.Path == "." || input.Path == ".." || path.Clean(input.Path) != input.Path || path.IsAbs(input.Path) || strings.HasPrefix(input.Path, "../") || strings.ContainsAny(input.Path, "\\\x00") || !hash(input.SHA256, 32) {
		return nil, ErrSource
	}
	parts := strings.Split(input.Path, "/")
	for i := range parts {
		info, err := root.Lstat(strings.Join(parts[:i+1], "/"))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrSource
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, ErrSource
		}
		if i == len(parts)-1 && !info.Mode().IsRegular() {
			return nil, ErrSource
		}
	}
	f, err := root.Open(input.Path)
	if err != nil {
		return nil, ErrSource
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxSourceBytes || info.Size() > int64(remaining) {
		return nil, ErrSource
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(min(MaxSourceBytes, remaining))+1))
	if err != nil || len(raw) > MaxSourceBytes || len(raw) > remaining || ctx.Err() != nil || digest(raw).SHA256 != input.SHA256 {
		return nil, ErrSource
	}
	return raw, nil
}
func prepare(ctx context.Context, raw []byte, root *os.Root, destination string) (snapshot, error) {
	s := snapshot{files: map[string]originalFile{}}
	m := &s.manifest
	if exactJSON(raw, MaxManifestBytes, m) != nil || m.Format != InputFormat || !strings.HasPrefix(m.Node, "0x") || len(m.Node) != 42 || len(m.Blocks) == 0 || len(m.Blocks) > MaxBlocks {
		return s, ErrSource
	}
	if _, err := hex.DecodeString(m.Node[2:]); err != nil {
		return s, ErrSource
	}
	copyFile := func(input FileInput) ([]byte, Digest, error) {
		if old, ok := s.files[input.Path]; ok && old.input != input {
			return nil, Digest{}, ErrSource
		}
		data, err := readOriginal(ctx, root, input, MaxReadBytes-s.readBytes)
		if err != nil {
			return nil, Digest{}, err
		}
		s.readBytes += len(data)
		sum := digest(data)
		name := filepath.Join(destination, filepath.FromSlash(input.Path))
		if old, ok := s.files[input.Path]; ok {
			if old.digest != sum {
				return nil, Digest{}, ErrSource
			}
		} else {
			if os.MkdirAll(filepath.Dir(name), 0700) != nil {
				return nil, Digest{}, ErrSource
			}
			f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
			if err != nil {
				return nil, Digest{}, ErrSource
			}
			_, err = f.Write(data)
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				return nil, Digest{}, ErrSource
			}
			s.files[input.Path] = originalFile{input: input, digest: sum}
		}
		return data, sum, nil
	}
	genesis, genesisDigest, err := copyFile(m.Genesis)
	if err != nil {
		return s, err
	}
	var config map[string]json.RawMessage
	if jsonmeta.Decode(genesis, MaxSourceBytes, false, &config) != nil || len(config["config"]) == 0 {
		return s, ErrSource
	}
	s.source = Snapshot{Format: InputFormat, Node: strings.ToLower(m.Node), Manifest: digest(raw), Genesis: genesisDigest, ConfigSHA256: digest(config["config"]).SHA256, Blocks: []BlockEvidence{}}
	totalGas := uint64(0)
	for i, input := range m.Blocks {
		n, ok := number(input.Index)
		if !ok || n != uint64(i) {
			return s, ErrSource
		}
		data, sum, err := copyFile(input.File)
		if err != nil {
			return s, err
		}
		block, err := codec.DecodeBlock(data)
		if err != nil || block.Header == nil || block.Header.Number.String() != input.Index {
			return s, ErrSource
		}
		encoded, err := codec.EncodeBlock(block)
		if err != nil || !bytes.Equal(data, encoded) {
			return s, ErrSource
		}
		h := block.Header
		if h.GasLimit > MaxBlockGas || i > 0 && h.GasUsed > MaxTotalGas-totalGas {
			return s, ErrSource
		}
		if i > 0 {
			totalGas += h.GasUsed
		}
		e := BlockEvidence{Index: input.Index, Hash: codec.BlockHash(h).Hex(), Parent: h.ParentHash.Hex(), StateRoot: h.Root.Hex(), TransactionRoot: h.TxHash.Hex(), ReceiptRoot: h.ReceiptHash.Hex(), GasUsed: strconv.FormatUint(h.GasUsed, 10), File: sum}
		if i > 0 && e.Parent != s.source.Blocks[i-1].Hash {
			return s, ErrSource
		}
		s.source.Blocks = append(s.source.Blocks, e)
		if len(block.Body) < 2 || !bytes.Equal(block.Body[1], []byte{0xc0}) || h.UncleHash != keccak.Sum256([]byte{0xc0}) {
			return s, ErrSource
		}
		txs, err := rlp.ListItems(block.Body[0])
		if err != nil {
			return s, ErrSource
		}
		if i == 0 && len(txs) != 0 {
			return s, ErrSource
		}
		for ordinal, tx := range txs {
			if len(s.transactions) >= MaxTransactions || len(tx) == 0 {
				return s, ErrSource
			}
			binary := []byte(tx)
			if tx[0] < 0xc0 {
				var rest []byte
				binary, rest, err = rlp.SplitString(tx)
				if err != nil || len(rest) != 0 {
					return s, ErrSource
				}
			}
			s.transactions = append(s.transactions, expectedTransaction{index: input.Index, ordinal: ordinal, hash: keccak.Sum256(binary).Hex(), blockHash: e.Hash})
		}
	}
	s.source.GenesisHash = s.source.Blocks[0].Hash
	return s, nil
}
func (s *snapshot) recheck(ctx context.Context, root *os.Root, destination string) error {
	for _, file := range s.files {
		data, err := readOriginal(ctx, root, file.input, MaxReadBytes-s.readBytes)
		if err != nil || digest(data) != file.digest {
			return ErrSource
		}
		s.readBytes += len(data)
		copyRoot, err := os.OpenRoot(destination)
		if err != nil {
			return ErrSource
		}
		copied, err := readOriginal(ctx, copyRoot, file.input, MaxSourceBytes)
		_ = copyRoot.Close()
		if err != nil || digest(copied) != file.digest {
			return ErrSource
		}
	}
	return nil
}
