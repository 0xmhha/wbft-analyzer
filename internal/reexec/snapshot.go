package reexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

var journalFile = regexp.MustCompile(`^[0-9]{20}\.wal(\.idx)?$`)

// Snapshot reconstructs a private reader directory from immutable file refs.
// Callers remove the returned directory after the helper exits.
func Snapshot(ctx context.Context, summary messages.Summary, refs []messages.ArchivedFile) (string, error) {
	if summary.Kind != "journal" || len(refs) == 0 || len(refs) != len(summary.Files) {
		return "", errors.New("journal file references unavailable")
	}
	byName := make(map[string]messages.ArchivedFile, len(refs))
	for _, f := range refs {
		if _, ok := byName[f.Name]; ok {
			return "", errors.New("duplicate journal file reference")
		}
		byName[f.Name] = f
	}
	dir, err := os.MkdirTemp("", "wbft-reexec-")
	if err != nil {
		return "", err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(dir)
		}
	}()
	for _, f := range summary.Files {
		ref, ok := byName[f.Name]
		if !ok || !journalFile.MatchString(f.Name) || ref.SHA256 != f.SHA256 || ref.Bytes != f.Bytes || f.Bytes < 0 || f.Bytes > 256<<20 || filepath.Base(ref.Path) != f.SHA256 {
			return "", errors.New("journal file reference mismatch")
		}
		if err = copyVerified(ctx, ref.Path, filepath.Join(dir, f.Name), f.Bytes, f.SHA256); err != nil {
			return "", err
		}
	}
	sum, err := messages.Fingerprint(ctx, messages.Input{ID: summary.ID, Kind: "journal", Node: summary.Node, Path: dir})
	if err != nil || sum.SHA256 != summary.SHA256 {
		return "", errors.New("reconstructed journal fingerprint mismatch")
	}
	success = true
	return dir, nil
}

func copyVerified(ctx context.Context, source, target string, size int64, digest string) error {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != size {
		return errors.New("stored input is not a private regular file")
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var total int64
	reader := io.LimitReader(in, size+1)
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		n, e := reader.Read(buf)
		if n > 0 {
			if _, err = out.Write(buf[:n]); err != nil {
				return err
			}
			_, _ = h.Write(buf[:n])
			total += int64(n)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
	}
	if total != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("stored input fingerprint mismatch")
	}
	return out.Sync()
}

// CopyObject makes a private bounded snapshot of one retained chain object.
func CopyObject(ctx context.Context, ref messages.ArchivedFile, target string) error {
	if ref.Bytes < 0 || ref.Bytes > 256<<20 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(ref.SHA256) || filepath.Base(ref.Path) != ref.SHA256 {
		return errors.New("invalid stored object reference")
	}
	return copyVerified(ctx, ref.Path, target, ref.Bytes, ref.SHA256)
}
