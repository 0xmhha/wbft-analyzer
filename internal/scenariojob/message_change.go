package scenariojob

import (
	"context"
	"os"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

// bindMessages is repeated at enqueue and execution. Immutable source scope
// and exact stored coordinates are checked before any model input is changed.
func (w *Worker) bindMessages(ctx context.Context, source registered, change scenario.NetworkChange) ([]scenario.RecordedMessageBinding, error) {
	if !change.IsMessageChange() {
		return nil, nil
	}
	release, err := w.store.DatasetReadLease(ctx, source.info.Dataset)
	if err != nil {
		return nil, err
	}
	defer release()
	_, network, err := w.store.ReexecDataset(ctx, source.info.Dataset)
	if err != nil {
		return nil, err
	}
	inputs, err := w.store.MessageInputs(ctx, source.info.Dataset)
	if err != nil {
		return nil, err
	}
	bound := []scenario.RecordedMessageBinding{}
	for _, selection := range change.Messages {
		var selected *scenario.Input
		for i, input := range source.info.TransportInputs {
			if input.ID == selection.Input {
				selected = &source.info.TransportInputs[i]
			}
		}
		if selected == nil {
			return nil, ErrChange
		}
		var summary *messages.Summary
		for i, input := range inputs {
			if input.Summary.ID == selection.Input {
				summary = &inputs[i].Summary
			}
		}
		if summary == nil || summary.SHA256 != selected.SHA256 || summary.Kind != selected.Kind || !strings.EqualFold(summary.Node, selected.Node) {
			return nil, ErrSource
		}
		row, err := w.store.MessageRecordAt(ctx, source.info.Dataset, selection.Input, selection.File, selection.Ordinal)
		if err != nil {
			return nil, ErrChange
		}
		if !messageInSourceScope(row, source) {
			return nil, ErrChange
		}
		files, err := w.store.InputFiles(ctx, source.info.Dataset, selection.Input)
		if err != nil {
			return nil, err
		}
		var dir string
		switch summary.Kind {
		case "journal":
			dir, err = reexec.Snapshot(ctx, *summary, files)
		case "frames":
			dir, err = reexec.SnapshotFrames(ctx, *summary, files)
		default:
			return nil, ErrChange
		}
		if err != nil {
			return nil, ErrSource
		}
		payload, code, readErr := messages.SelectedPayload(ctx, messages.Prepared{Input: messages.Input{ID: summary.ID, Kind: summary.Kind, Node: summary.Node, Path: dir}, Summary: *summary}, row, network.ChainID, network.GenesisHash)
		_ = os.RemoveAll(dir)
		if readErr != nil {
			return nil, ErrChange
		}
		binding, err := scenario.BindRecordedMessage(selection, row, payload, code, source.info.Nodes)
		if err != nil {
			return nil, ErrChange
		}
		binding.Native.InputSHA256 = summary.SHA256
		bound = append(bound, binding)
	}
	if len(bound) == 2 && (bound[0].Effective.Receiver != bound[1].Effective.Receiver || bound[0].Effective == bound[1].Effective) {
		return nil, ErrChange
	}
	return bound, nil
}
