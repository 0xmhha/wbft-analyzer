package reexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"io"
	"os"
	"path/filepath"
)

func RetainChain(ctx context.Context, path, directory string) (messages.ArchivedFile, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return messages.ArchivedFile{}, errors.New("chain must be a regular file at most 256MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return messages.ArchivedFile{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1))
	if err != nil || n > 256<<20 {
		return messages.ArchivedFile{}, errors.New("chain size limit exceeded")
	}
	sum := hex.EncodeToString(h.Sum(nil))
	name := filepath.Base(path)
	p := messages.Prepared{Input: messages.Input{ID: "chain", Path: filepath.Dir(path)}, Summary: messages.Summary{Files: []messages.File{{Name: name, Bytes: n, SHA256: sum}}}}
	out, err := messages.Archive(ctx, directory, []messages.Prepared{p})
	if err != nil {
		return messages.ArchivedFile{}, err
	}
	return out["chain"][0], nil
}
