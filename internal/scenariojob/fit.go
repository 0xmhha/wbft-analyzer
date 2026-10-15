package scenariojob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type FitRequest struct {
	TransportManifest string
	Options           scenario.FitOptions
	ChainPath         string
	RuntimeManifest   string
	EventManifest     string
	Snapshot          *scenario.SourceSnapshot
}

// FitDataset reconstructs verified private snapshots and keeps their bytes
// outside the database. A partial fitting report is never made executable.
func FitDataset(ctx context.Context, s *store.Store, r FitRequest) (scenario.Fitted, error) {
	fitted, _, err := PrepareDataset(ctx, s, r)
	return fitted, err
}

func PrepareDataset(ctx context.Context, s *store.Store, r FitRequest) (scenario.Fitted, scenario.SourceSnapshot, error) {
	out := scenario.Fitted{}
	snapshot := scenario.SourceSnapshot{Events: []scenario.EventObject{}}
	release, err := s.DatasetReadLease(ctx, r.Options.Dataset)
	if err != nil {
		return out, snapshot, err
	}
	defer release()
	dataset, network, err := s.ReexecDataset(ctx, r.Options.Dataset)
	if err != nil {
		return out, snapshot, err
	}
	if dataset.Status != "complete" {
		return out, snapshot, errors.New("scenario source dataset incomplete")
	}
	inputs, err := s.MessageInputs(ctx, dataset.ID)
	if err != nil {
		return out, snapshot, err
	}
	dirs := []string{}
	defer func() {
		for _, d := range dirs {
			_ = os.RemoveAll(d)
		}
	}()
	r.Options.Journals = []messages.Prepared{}
	r.Options.Frames = []messages.Prepared{}
	for _, input := range inputs {
		if input.Summary.Kind != "journal" && input.Summary.Kind != "frames" {
			continue
		}
		refs, err := s.InputFiles(ctx, dataset.ID, input.Summary.ID)
		if err != nil {
			return out, snapshot, err
		}
		var directory string
		if input.Summary.Kind == "journal" {
			directory, err = reexec.Snapshot(ctx, input.Summary, refs)
		} else {
			directory, err = reexec.SnapshotFrames(ctx, input.Summary, refs)
		}
		if err != nil {
			return out, snapshot, err
		}
		dirs = append(dirs, directory)
		prepared := messages.Prepared{Input: messages.Input{ID: input.Summary.ID, Kind: input.Summary.Kind, Node: input.Summary.Node, Path: directory}, Summary: input.Summary}
		if input.Summary.Kind == "journal" {
			r.Options.Journals = append(r.Options.Journals, prepared)
		} else {
			r.Options.Frames = append(r.Options.Frames, prepared)
		}
	}
	storage, err := s.InputStorageDirectory(ctx, dataset.ID)
	if err != nil {
		return out, snapshot, err
	}
	if r.Snapshot == nil {
		snapshot.Chain, err = reexec.RetainChain(ctx, r.ChainPath, storage)
		if err != nil {
			return out, snapshot, err
		}
	} else {
		snapshot = *r.Snapshot
		if len(snapshot.Events) > 256 || len(snapshot.Runtime) > 256 {
			return out, snapshot, errors.New("too many retained event inputs")
		}
		for _, ref := range snapshot.Objects() {
			if filepath.Dir(ref.Path) != storage {
				return out, snapshot, errors.New("retained source outside owned storage")
			}
		}
	}
	tmp, err := os.MkdirTemp("", "wbft-scenario-chain-")
	if err != nil {
		return out, snapshot, err
	}
	dirs = append(dirs, tmp)
	if err := reexec.CopyObject(ctx, snapshot.Chain, filepath.Join(tmp, "chain.rlp")); err != nil {
		return out, snapshot, err
	}
	r.Options.Chain, err = os.ReadFile(filepath.Join(tmp, "chain.rlp"))
	if err != nil {
		return out, snapshot, err
	}
	r.Options.CoreCommit = reexec.LinkedCommit()
	if r.Options.CoreCommit == "unknown" {
		return out, snapshot, errors.New("scenario core version unavailable")
	}
	if r.Snapshot == nil && r.EventManifest != "" {
		manifest, err := logs.LoadManifest(r.EventManifest)
		if err != nil {
			return out, snapshot, err
		}
		if manifest.Network.ChainID != network.ChainID || manifest.Network.GenesisHash != network.GenesisHash {
			return out, snapshot, errors.New("event and message networks differ")
		}
		plan, err := logs.Prepare(ctx, manifest)
		if err != nil {
			return out, snapshot, err
		}
		if len(plan.Inputs) > 256 {
			return out, snapshot, errors.New("too many event inputs")
		}
		var total int64
		for _, in := range plan.Inputs {
			if total > (16<<30)-in.Summary.Bytes {
				return out, snapshot, errors.New("event storage bounds exceeded")
			}
			total += in.Summary.Bytes
			object, err := retainEvent(ctx, in, storage)
			if err != nil {
				return out, snapshot, err
			}
			snapshot.Events = append(snapshot.Events, object)
		}
	}
	r.Options.Events = []scenario.EventInput{}
	for _, object := range snapshot.Events {
		if !logs.Identifier(object.Source.ID) || object.Source.Kind != "events" {
			return out, snapshot, errors.New("invalid retained event identity")
		}
		if len(object.Files) < 1 || len(object.Files) > 4 {
			return out, snapshot, errors.New("invalid retained event stream")
		}
		readers := []io.Reader{}
		files := []*os.File{}
		closeFiles := func() {
			for _, file := range files {
				_ = file.Close()
			}
		}
		for i, ref := range object.Files {
			target := filepath.Join(tmp, "event-"+object.Source.ID+"-"+fmt.Sprint(i))
			if err := reexec.CopyObject(ctx, ref, target); err != nil {
				closeFiles()
				return out, snapshot, err
			}
			file, err := os.Open(target)
			if err != nil {
				closeFiles()
				return out, snapshot, err
			}
			files = append(files, file)
			readers = append(readers, file)
		}
		event, err := scenario.InspectEvents(ctx, object.Source, io.MultiReader(readers...))
		closeFiles()
		if err != nil {
			return out, snapshot, err
		}
		r.Options.Events = append(r.Options.Events, event)
	}
	if r.Snapshot == nil && r.RuntimeManifest != "" {
		snapshot.Runtime, err = retainRuntimeObservations(ctx, r.RuntimeManifest, storage, network.ChainID, network.GenesisHash)
		if err != nil {
			return out, snapshot, err
		}
	}
	r.Options.RuntimeObservations = []scenario.RuntimeObservation{}
	for _, object := range snapshot.Runtime {
		if object.File.Bytes < 1 || object.File.Bytes > 64<<20 || object.File.SHA256 != object.Source.SHA256 {
			return out, snapshot, ErrSource
		}
		target := filepath.Join(tmp, "runtime-"+object.Source.ID)
		if !logs.Identifier(object.Source.ID) {
			return out, snapshot, ErrSource
		}
		if err := reexec.CopyObject(ctx, object.File, target); err != nil {
			return out, snapshot, err
		}
		f, err := os.Open(target)
		if err != nil {
			return out, snapshot, err
		}
		observed, e := scenario.InspectRuntimeObservation(object.Source, f)
		_ = f.Close()
		if e != nil {
			return out, snapshot, e
		}
		r.Options.RuntimeObservations = append(r.Options.RuntimeObservations, observed)
	}
	if r.Snapshot == nil && r.TransportManifest != "" {
		snapshot.Transport, err = retainTransportEvidence(ctx, r.TransportManifest, storage, network.ChainID, network.GenesisHash)
		if err != nil {
			return out, snapshot, err
		}
	}
	r.Options.TransportEvidence = nil
	if snapshot.Transport != nil {
		r.Options.TransportEvidence, err = readTransportEvidence(ctx, *snapshot.Transport, tmp)
		if err != nil {
			return out, snapshot, err
		}
	}
	fitted, err := scenario.Fit(ctx, r.Options)
	return fitted, snapshot, err
}
