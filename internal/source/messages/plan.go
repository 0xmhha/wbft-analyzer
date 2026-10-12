package messages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
)

var addressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
var hashPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var journalName = regexp.MustCompile(`^[0-9]{20}\.wal(\.idx)?$`)
var frameName = regexp.MustCompile(`^frames-[A-Za-z0-9_.-]{1,128}\.jsonl$`)

func LoadManifest(path string) (Manifest, error) {
	var m Manifest
	f, e := os.Open(path)
	if e != nil {
		return m, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return m, errors.New("invalid message manifest size")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return m, errors.New("invalid message manifest")
	}
	if d.Decode(new(any)) != io.EOF {
		return m, errors.New("trailing manifest data")
	}
	for i := range m.Inputs {
		if !filepath.IsAbs(m.Inputs[i].Path) {
			m.Inputs[i].Path = filepath.Join(filepath.Dir(path), m.Inputs[i].Path)
		}
	}
	return m, nil
}

func Prepare(ctx context.Context, m Manifest) ([]Prepared, json.RawMessage, error) {
	n, ok := new(big.Int).SetString(m.Network.ChainID, 10)
	if m.Format != Format || !logs.Identifier(m.Name) || !ok || n.Sign() < 0 || n.BitLen() > 512 || n.String() != m.Network.ChainID || !hashPattern.MatchString(m.Network.GenesisHash) || len(m.Inputs) < 1 || len(m.Inputs) > 100 {
		return nil, nil, errors.New("invalid message identity or inputs")
	}
	if m.Clock.Model != "unknown" && m.Clock.Model != "shared-host" && m.Clock.Model != "ntp" {
		return nil, nil, errors.New("invalid message clock model")
	}
	if m.Clock.Model == "ntp" {
		if m.Clock.SkewMS == nil || *m.Clock.SkewMS < 0 || *m.Clock.SkewMS > 86400000 {
			return nil, nil, errors.New("ntp needs bounded skew_ms")
		}
	} else if m.Clock.SkewMS != nil {
		return nil, nil, errors.New("skew_ms applies only to ntp")
	}
	ids := map[string]bool{}
	out := []Prepared{}
	sums := []Summary{}
	for _, in := range m.Inputs {
		if !logs.Identifier(in.ID) || ids[in.ID] || !addressPattern.MatchString(in.Node) || (in.Kind != "journal" && in.Kind != "frames") {
			return nil, nil, errors.New("invalid message input")
		}
		ids[in.ID] = true
		in.Node = strings.ToLower(in.Node)
		sum, e := Fingerprint(ctx, in)
		if e != nil {
			return nil, nil, e
		}
		if in.SHA256 != "" && sum.SHA256 != in.SHA256 {
			return nil, nil, errors.New("message input checksum mismatch")
		}
		out = append(out, Prepared{in, sum})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Input.ID < out[j].Input.ID })
	for _, p := range out {
		sums = append(sums, p.Summary)
	}
	meta, _ := json.Marshal(struct {
		Format     string    `json:"format"`
		Normalizer string    `json:"normalizer"`
		Clock      Clock     `json:"clock"`
		Inputs     []Summary `json:"inputs"`
	}{Format, Normalizer, m.Clock, sums})
	return out, meta, nil
}

// Fingerprint binds every reader-visible file, including content-addressed
// payloads. It rejects symlinks and unrecognized artifact names. A completed
// dataset must match this fingerprint again after streaming normalization.
func Fingerprint(ctx context.Context, in Input) (Summary, error) {
	s := Summary{ID: in.ID, Kind: in.Kind, Node: strings.ToLower(in.Node), Files: []File{}}
	root, e := os.OpenRoot(in.Path)
	if e != nil {
		return s, errors.New("cannot open message input")
	}
	defer root.Close()
	dataFiles := 0
	e = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return errors.New("cannot enumerate message input")
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("message input contains symlink")
		}
		if d.IsDir() {
			return nil
		}
		allowed := false
		if in.Kind == "journal" {
			allowed = journalName.MatchString(name)
			if allowed && strings.HasSuffix(name, ".wal") {
				dataFiles++
			}
		} else {
			allowed = frameName.MatchString(name)
			if allowed {
				dataFiles++
			} else {
				parts := strings.Split(name, "/")
				allowed = len(parts) == 3 && parts[0] == "payloads" && shaPattern.MatchString(parts[2]) && parts[1] == parts[2][:2]
			}
		}
		if !allowed {
			return errors.New("unsupported file in message input")
		}
		if len(s.Files) >= 100000 {
			return errors.New("too many message artifact files")
		}
		f, e := root.Open(name)
		if e != nil {
			return errors.New("cannot read message artifact")
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() {
			return errors.New("message artifact is not regular")
		}
		if in.Kind == "journal" && info.Size() > 256<<20 {
			return errors.New("journal segment exceeds 256MiB")
		}
		h := sha256.New()
		var count int64
		buf := make([]byte, 64<<10)
		for {
			if e = ctx.Err(); e != nil {
				return e
			}
			n, er := f.Read(buf)
			if n > 0 {
				_, _ = h.Write(buf[:n])
				count += int64(n)
			}
			if er == io.EOF {
				break
			}
			if er != nil {
				return errors.New("cannot hash message artifact")
			}
		}
		s.Bytes += count
		s.Files = append(s.Files, File{name, count, hex.EncodeToString(h.Sum(nil))})
		return nil
	})
	if e != nil {
		return s, e
	}
	if dataFiles == 0 {
		return s, errors.New("message input has no records")
	}
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].Name < s.Files[j].Name })
	b, _ := json.Marshal(s.Files)
	h := sha256.Sum256(b)
	s.SHA256 = hex.EncodeToString(h[:])
	return s, nil
}
