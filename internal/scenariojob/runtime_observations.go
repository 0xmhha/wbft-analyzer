package scenariojob

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

type runtimeManifest struct {
	Format  string        `json:"format"`
	Network logs.Network  `json:"network"`
	Inputs  []runtimeFile `json:"inputs"`
}
type runtimeFile struct {
	ID   string `json:"id"`
	Node string `json:"node"`
	Path string `json:"path"`
	SHA  string `json:"sha256"`
}

func retainRuntimeObservations(ctx context.Context, path, storage, chain, genesis string) ([]scenario.RuntimeObject, error) {
	out := []scenario.RuntimeObject{}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() > 256<<10 {
		return out, ErrSource
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return out, ErrSource
	}
	var m runtimeManifest
	if whatif.DecodeJSON(raw, &m) != nil || m.Format != "wbft-analyzer-runtime-manifest/1" || m.Network.ChainID != chain || m.Network.GenesisHash != genesis || len(m.Inputs) == 0 || len(m.Inputs) > 256 {
		return out, ErrSource
	}
	seen := map[string]bool{}
	nodes := map[string]bool{}
	var total int64
	for _, in := range m.Inputs {
		if !logs.Identifier(in.ID) || seen[in.ID] || nodes[in.Node] {
			return out, ErrSource
		}
		seen[in.ID] = true
		nodes[in.Node] = true
		file := in.Path
		if !filepath.IsAbs(file) {
			file = filepath.Join(filepath.Dir(path), file)
		}
		st, e := os.Lstat(file)
		if e != nil || !st.Mode().IsRegular() || st.Size() > runtimeobs.MaxBytes {
			return out, ErrSource
		}
		total += st.Size()
		if total > 1<<30 {
			return out, ErrSource
		}
		c, e := runtimeobs.Load(file)
		if e != nil || c.Node != in.Node || c.SourceSHA != in.SHA {
			return out, errors.New("runtime manifest source changed")
		}
		p := messages.Prepared{Input: messages.Input{ID: in.ID, Path: filepath.Dir(file)}, Summary: messages.Summary{Files: []messages.File{{Name: filepath.Base(file), Bytes: st.Size(), SHA256: in.SHA}}}}
		archived, e := messages.Archive(ctx, storage, []messages.Prepared{p})
		if e != nil {
			return out, e
		}
		out = append(out, scenario.RuntimeObject{Source: scenario.Input{ID: in.ID, Kind: "runtime", Node: in.Node, SHA256: in.SHA}, File: archived[in.ID][0]})
	}
	return out, nil
}
