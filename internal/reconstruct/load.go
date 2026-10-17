package reconstruct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
)

var addressPattern = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
var hashPattern = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
var runIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func LoadManifest(ctx context.Context, path string) (Manifest, error) {
	raw, err := readFile(ctx, path, 1<<20)
	if err != nil {
		return Manifest{}, errors.New("reconstruction manifest unavailable")
	}
	var m Manifest
	if jsonmeta.Decode(raw, 1<<20, true, &m) != nil || !validManifest(m) {
		return Manifest{}, errors.New("invalid reconstruction manifest")
	}
	for _, file := range []*File{&m.Log, m.Frames, m.Runtime, m.Chain} {
		if file != nil && !filepath.IsAbs(file.Path) {
			file.Path = filepath.Join(filepath.Dir(path), file.Path)
		}
	}
	return m, nil
}

func validManifest(m Manifest) bool {
	n, ok := new(big.Int).SetString(m.Network.ChainID, 10)
	if !validScopes(m) || m.Format != ManifestFormat || !addressPattern.MatchString(m.Node) || !hashPattern.MatchString(m.Network.GenesisHash) || !ok || n.Sign() < 0 || n.BitLen() > 512 || n.String() != m.Network.ChainID {
		return false
	}
	for _, file := range []*File{&m.Log, m.Frames, m.Runtime, m.Chain} {
		if file != nil && (strings.TrimSpace(file.Path) == "" || !shaPattern.MatchString(file.SHA256)) {
			return false
		}
	}
	return true
}

// readFile refuses non-regular inputs before opening them and returns a
// bounded immutable byte snapshot. Callers verify its digest before projection.
func readFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("reconstruction source is unavailable or oversized")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("reconstruction source unavailable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("reconstruction source changed while opening")
	}
	var out bytes.Buffer
	buf := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := f.Read(buf)
		if int64(out.Len()+n) > limit {
			return nil, errors.New("reconstruction source exceeds limit")
		}
		out.Write(buf[:n])
		if err == io.EOF {
			return out.Bytes(), nil
		}
		if err != nil {
			return nil, errors.New("reconstruction source read failed")
		}
	}
}

func snapshot(ctx context.Context, file File, limit int64) ([]byte, error) {
	raw, err := readFile(ctx, file.Path, limit)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != file.SHA256 {
		return nil, errors.New("reconstruction source checksum mismatch")
	}
	return raw, nil
}

func heightRange(from, to string) ([]Height, map[string]int, error) {
	a, ok := new(big.Int).SetString(from, 10)
	b, valid := new(big.Int).SetString(to, 10)
	if !ok || !valid || a.Sign() <= 0 || a.BitLen() > 256 || b.BitLen() > 256 || a.String() != from || b.String() != to || b.Cmp(a) < 0 {
		return nil, nil, errors.New("invalid reconstruction height range")
	}
	delta := new(big.Int).Sub(b, a)
	if !delta.IsInt64() || delta.Int64() >= MaxHeights {
		return nil, nil, errors.New("reconstruction range exceeds 10000 heights")
	}
	rows := make([]Height, 0, int(delta.Int64())+1)
	index := map[string]int{}
	for n := new(big.Int).Set(a); n.Cmp(b) <= 0; n.Add(n, big.NewInt(1)) {
		value := n.String()
		index[value] = len(rows)
		rows = append(rows, Height{Height: value, Status: "not_possible", Issues: []string{}, Evidence: []Evidence{}})
	}
	return rows, index, nil
}
