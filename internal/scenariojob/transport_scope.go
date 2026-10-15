package scenariojob

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
)

type transportFile struct {
	ID   string `json:"id"`
	Node string `json:"node"`
	Path string `json:"path"`
	SHA  string `json:"sha256"`
}
type transportManifest struct {
	Format     string          `json:"format"`
	ID         string          `json:"id"`
	Network    logs.Network    `json:"network"`
	Controller transportFile   `json:"controller"`
	Headers    []transportFile `json:"headers"`
	Windows    []struct {
		Input       string        `json:"input"`
		Certificate transportFile `json:"certificate"`
	} `json:"windows"`
}

func decodeTransportManifest(raw []byte) (transportManifest, error) {
	var m transportManifest
	if jsonmeta.Decode(raw, 1<<20, true, &m) != nil || m.Format != "wbft-analyzer-transport-manifest/1" || !logs.Identifier(m.ID) || len(m.Headers) < 2 || len(m.Headers) > 256 || len(m.Windows) < 2 || len(m.Windows) > 256 || m.Controller.Node != "network" {
		return m, ErrSource
	}
	seen := map[string]bool{m.ID: true}
	check := func(f transportFile) bool {
		if !logs.Identifier(f.ID) || seen[f.ID] || f.Node == "" || len(f.Path) == 0 || len(f.Path) > 4096 || len(f.SHA) != 64 || f.SHA != strings.ToLower(f.SHA) {
			return false
		}
		seen[f.ID] = true
		return true
	}
	if !check(m.Controller) {
		return m, ErrSource
	}
	for _, h := range m.Headers {
		if !check(h) {
			return m, ErrSource
		}
	}
	for _, w := range m.Windows {
		if !logs.Identifier(w.Input) || !check(w.Certificate) {
			return m, ErrSource
		}
	}
	return m, nil
}

func retainTransportEvidence(ctx context.Context, path, storage, chain, genesis string) (*scenario.TransportSnapshot, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, ErrSource
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrSource
	}
	m, err := decodeTransportManifest(raw)
	if err != nil || m.Network.ChainID != chain || m.Network.GenesisHash != genesis {
		return nil, ErrSource
	}
	decl, err := reexec.RetainChain(ctx, path, storage)
	if err != nil {
		return nil, ErrSource
	}
	out := &scenario.TransportSnapshot{Declaration: scenario.EvidenceObject{Source: scenario.Input{ID: m.ID, Kind: "transport-manifest", Node: "network", SHA256: decl.SHA256}, File: decl}, Headers: []scenario.EvidenceObject{}, Windows: []scenario.TransportWindowObject{}}
	var total int64
	retain := func(f transportFile, kind string) (scenario.EvidenceObject, error) {
		file := f.Path
		if !filepath.IsAbs(file) {
			file = filepath.Join(filepath.Dir(path), file)
		}
		object, err := reexec.RetainChain(ctx, file, storage)
		if err != nil || object.SHA256 != f.SHA {
			return scenario.EvidenceObject{}, ErrSource
		}
		total += object.Bytes
		if total > 2<<30 {
			return scenario.EvidenceObject{}, ErrSource
		}
		return scenario.EvidenceObject{Source: scenario.Input{ID: f.ID, Kind: kind, Node: f.Node, SHA256: f.SHA}, File: object}, nil
	}
	out.Controller, err = retain(m.Controller, "transport-controller")
	if err != nil {
		return nil, err
	}
	for _, h := range m.Headers {
		o, err := retain(h, "transport-headers")
		if err != nil {
			return nil, err
		}
		out.Headers = append(out.Headers, o)
	}
	for _, w := range m.Windows {
		o, err := retain(w.Certificate, "transport-certificate")
		if err != nil {
			return nil, err
		}
		out.Windows = append(out.Windows, scenario.TransportWindowObject{Input: w.Input, Certificate: o})
	}
	return out, nil
}

func readTransportEvidence(ctx context.Context, s scenario.TransportSnapshot, tmp string) (*scenario.TransportEvidence, error) {
	if len(s.Headers) < 2 || len(s.Headers) > 256 || len(s.Windows) < 2 || len(s.Windows) > 256 {
		return nil, ErrSource
	}
	var total int64
	read := func(o scenario.EvidenceObject, limit int64) (scenario.EvidenceDocument, error) {
		if !logs.Identifier(o.Source.ID) || o.File.SHA256 != o.Source.SHA256 || o.File.Bytes < 1 || o.File.Bytes > limit {
			return scenario.EvidenceDocument{}, ErrSource
		}
		total += o.File.Bytes
		if total > 2<<30 {
			return scenario.EvidenceDocument{}, ErrSource
		}
		target := filepath.Join(tmp, "transport-"+o.Source.ID)
		if err := reexec.CopyObject(ctx, o.File, target); err != nil {
			return scenario.EvidenceDocument{}, err
		}
		raw, err := os.ReadFile(target)
		if err != nil {
			return scenario.EvidenceDocument{}, err
		}
		return scenario.EvidenceDocument{Source: o.Source, Bytes: raw}, nil
	}
	declaration, err := read(s.Declaration, 1<<20)
	if err != nil {
		return nil, err
	}
	m, err := decodeTransportManifest(declaration.Bytes)
	if err != nil || s.Declaration.Source.ID != m.ID || s.Declaration.Source.Kind != "transport-manifest" || s.Declaration.Source.Node != "network" || len(m.Headers) != len(s.Headers) || len(m.Windows) != len(s.Windows) {
		return nil, ErrSource
	}
	matches := func(f transportFile, o scenario.EvidenceObject, kind string) bool {
		return f.ID == o.Source.ID && f.Node == o.Source.Node && f.SHA == o.Source.SHA256 && o.Source.Kind == kind
	}
	if !matches(m.Controller, s.Controller, "transport-controller") {
		return nil, ErrSource
	}
	controller, err := read(s.Controller, 1<<20)
	if err != nil {
		return nil, err
	}
	out := &scenario.TransportEvidence{Declaration: declaration.Source, Controller: controller, Headers: []scenario.EvidenceDocument{}, Windows: []scenario.TransportWindowEvidence{}}
	for i, h := range s.Headers {
		if !matches(m.Headers[i], h, "transport-headers") {
			return nil, ErrSource
		}
		doc, err := read(h, 64<<20)
		if err != nil {
			return nil, err
		}
		out.Headers = append(out.Headers, doc)
	}
	for i, w := range s.Windows {
		if m.Windows[i].Input != w.Input || !matches(m.Windows[i].Certificate, w.Certificate, "transport-certificate") {
			return nil, ErrSource
		}
		doc, err := read(w.Certificate, 64<<10)
		if err != nil {
			return nil, err
		}
		out.Windows = append(out.Windows, scenario.TransportWindowEvidence{Input: w.Input, Certificate: doc})
	}
	return out, nil
}
