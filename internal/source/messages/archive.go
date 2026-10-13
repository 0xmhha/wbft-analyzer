package messages

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// ArchivedFile binds a local, private object to its original file name.
// Only these references cross the persistence boundary, never file bytes.
type ArchivedFile struct {
	Name   string
	SHA256 string
	Bytes  int64
	Path   string
}

const maxArchiveBytes int64 = 16 << 30
const maxArchiveFile int64 = 256 << 20

// Archive retains fingerprinted input files as immutable SHA256 objects.
// An existing object must verify; corrupted objects are never overwritten.
func Archive(ctx context.Context, directory string, plan []Prepared) (map[string][]ArchivedFile, error) {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("input storage must be a private directory")
	}
	dst, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	defer dst.Close()
	var total int64
	for _, p := range plan {
		for _, f := range p.Summary.Files {
			if f.Bytes < 0 || f.Bytes > maxArchiveFile || total > maxArchiveBytes-f.Bytes || !shaPattern.MatchString(f.SHA256) {
				return nil, errors.New("input storage bounds exceeded")
			}
			total += f.Bytes
		}
	}
	out := make(map[string][]ArchivedFile, len(plan))
	for _, p := range plan {
		src, err := os.OpenRoot(p.Input.Path)
		if err != nil {
			return nil, err
		}
		files, err := archiveInput(ctx, src, dst, abs, p.Summary.Files)
		src.Close()
		if err != nil {
			return nil, err
		}
		out[p.Input.ID] = files
	}
	// Persist directory entries before committing their database references.
	dir, err := dst.Open(".")
	if err != nil {
		return nil, err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return nil, err
	}
	return out, nil
}

func archiveInput(ctx context.Context, src, dst *os.Root, directory string, files []File) ([]ArchivedFile, error) {
	out := make([]ArchivedFile, 0, len(files))
	for _, f := range files {
		if err := archiveFile(ctx, src, dst, f); err != nil {
			return nil, err
		}
		out = append(out, ArchivedFile{f.Name, f.SHA256, f.Bytes, filepath.Join(directory, f.SHA256)})
	}
	return out, nil
}

func archiveFile(ctx context.Context, src, dst *os.Root, f File) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Recheck the source even when an identical object is already retained.
	info, err := src.Lstat(f.Name)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("input storage source is not regular")
	}
	in, err := src.Open(f.Name)
	if err != nil {
		return err
	}
	defer in.Close()
	if info, err = in.Stat(); err != nil || !info.Mode().IsRegular() || info.Size() != f.Bytes {
		return errors.New("input storage source changed")
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := ".pending-" + hex.EncodeToString(nonce[:])
	writer, err := dst.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = dst.Remove(tmp) }()
	h := sha256.New()
	n, err := copyArchive(ctx, io.MultiWriter(writer, h), io.LimitReader(in, f.Bytes+1))
	if err == nil && (n != f.Bytes || hex.EncodeToString(h.Sum(nil)) != f.SHA256) {
		err = errors.New("input storage source fingerprint mismatch")
	}
	if err == nil {
		err = writer.Sync()
	}
	closeErr := writer.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// Link publishes without replacing a concurrent or existing object.
	if err = dst.Link(tmp, f.SHA256); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err = dst.Lstat(f.SHA256)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != f.Bytes {
		return errors.New("input storage object is not a private regular file")
	}
	object, err := dst.Open(f.SHA256)
	if err != nil {
		return err
	}
	defer object.Close()
	h.Reset()
	n, err = copyArchive(ctx, h, io.LimitReader(object, f.Bytes+1))
	if err != nil {
		return err
	}
	if n != f.Bytes || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return errors.New("input storage object fingerprint mismatch")
	}
	return nil
}

func copyArchive(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 64<<10)
	var total int64
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
