package scenariojob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

const eventChunkBytes int64 = 256 << 20

// retainEvent snapshots only the fingerprinted complete-line prefix. A later
// append never changes the retained stream; a prefix mutation is refused.
func retainEvent(ctx context.Context, in logs.PreparedInput, directory string) (scenario.EventObject, error) {
	return retainEventChunks(ctx, in, directory, eventChunkBytes)
}
func retainEventChunks(ctx context.Context, in logs.PreparedInput, directory string, chunkSize int64) (scenario.EventObject, error) {
	out := scenario.EventObject{Source: scenario.Input{ID: in.Summary.ID, Kind: "events", Node: in.Summary.Node, SHA256: in.Summary.SHA256}, Files: []messages.ArchivedFile{}}
	if chunkSize < 1 || chunkSize > eventChunkBytes || in.Summary.Kind != "events" || in.Summary.Bytes < 1 || in.Summary.Bytes > 1<<30 {
		return out, ErrSource
	}
	info, err := os.Lstat(in.Path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < in.Summary.Bytes {
		return out, ErrSource
	}
	input, err := os.Open(in.Path)
	if err != nil {
		return out, err
	}
	defer input.Close()
	actual, err := input.Stat()
	if err != nil || !os.SameFile(info, actual) || !actual.Mode().IsRegular() {
		return out, ErrSource
	}
	tmp, err := os.MkdirTemp("", "wbft-scenario-event-")
	if err != nil {
		return out, err
	}
	defer os.RemoveAll(tmp)
	plan := messages.Prepared{Input: messages.Input{ID: out.Source.ID, Path: tmp}, Summary: messages.Summary{Files: []messages.File{}}}
	whole := sha256.New()
	remaining := in.Summary.Bytes
	for part := 0; remaining > 0; part++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		size := min(remaining, chunkSize)
		name := fmt.Sprintf("events-%04d.jsonl", part)
		f, err := os.OpenFile(filepath.Join(tmp, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return out, err
		}
		h := sha256.New()
		n, err := copyPrefix(ctx, io.MultiWriter(f, h, whole), io.NewSectionReader(input, in.Summary.Bytes-remaining, size))
		closeErr := f.Close()
		if err != nil {
			return out, err
		}
		if closeErr != nil {
			return out, closeErr
		}
		if n != size {
			return out, ErrSource
		}
		plan.Summary.Files = append(plan.Summary.Files, messages.File{Name: name, Bytes: size, SHA256: hex.EncodeToString(h.Sum(nil))})
		remaining -= size
	}
	if hex.EncodeToString(whole.Sum(nil)) != in.Summary.SHA256 {
		return out, errors.New("event prefix fingerprint changed")
	}
	objects, err := messages.Archive(ctx, directory, []messages.Prepared{plan})
	if err != nil {
		return out, err
	}
	out.Files = objects[out.Source.ID]
	return out, nil
}
func copyPrefix(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	var total int64
	buf := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := src.Read(buf)
		if n > 0 {
			written, e := dst.Write(buf[:n])
			total += int64(written)
			if e != nil {
				return total, e
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}
