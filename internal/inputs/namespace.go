// Package inputs owns private dataset input directories. Object bytes stay
// outside PostgreSQL; ownership markers are never served by the API.
package inputs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var ErrOwnership = errors.New("input storage ownership is unavailable or changed")
var tokenPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var objectPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var ownerPendingPattern = regexp.MustCompile(`^\.owner-pending-[0-9a-f]{32}$`)
var pendingPattern = regexp.MustCompile(`^\.pending-[0-9a-f]{32}$`)

const marker = ".owner.json"
const maxEntries = 100000

type Namespace struct{ Root, Token, Owner string }
type ownership struct{ Version, Token, Owner string }

func NewToken() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func PrivateRoot(directory string) (string, error) {
	abs, e := filepath.Abs(directory)
	if e != nil {
		return "", e
	}
	if e = os.MkdirAll(abs, 0700); e != nil {
		return "", e
	}
	abs, e = filepath.EvalSymlinks(abs)
	if e != nil {
		return "", e
	}
	info, e := os.Lstat(abs)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", ErrOwnership
	}
	return abs, nil
}
func (n Namespace) Directory() string { return filepath.Join(n.Root, "datasets", n.Token) }
func (n Namespace) valid() bool {
	return filepath.IsAbs(n.Root) && tokenPattern.MatchString(n.Token) && objectPattern.MatchString(n.Owner)
}
func (n Namespace) expected() []byte {
	b, _ := json.Marshal(ownership{"wbft-input-owner/1", n.Token, n.Owner})
	return b
}

// Ensure creates only an empty owned directory, or verifies its existing marker.
func (n Namespace) Ensure() error {
	if !n.valid() {
		return ErrOwnership
	}
	root, e := PrivateRoot(n.Root)
	if e != nil || root != n.Root {
		return ErrOwnership
	}
	parent := filepath.Join(root, "datasets")
	if e = os.Mkdir(parent, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return e
	}
	info, e := os.Lstat(parent)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return ErrOwnership
	}
	if e = os.Mkdir(n.Directory(), 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return e
	}
	dir, e := n.open()
	if e != nil {
		return e
	}
	defer dir.Close()
	if _, e = dir.Lstat(marker); errors.Is(e, os.ErrNotExist) {
		f, err := dir.Open(".")
		if err != nil {
			return err
		}
		entries, err := f.ReadDir(101)
		f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if len(entries) > 100 {
			return ErrOwnership
		}
		for _, entry := range entries {
			info, err := dir.Lstat(entry.Name())
			if err != nil || !ownerPendingPattern.MatchString(entry.Name()) || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1024 {
				return ErrOwnership
			}
		}
		// Only interrupted marker creation may occupy an unclaimed directory.
		for _, entry := range entries {
			if err = dir.Remove(entry.Name()); err != nil {
				return err
			}
		}
		nonce, err := NewToken()
		if err != nil {
			return err
		}
		temporary := ".owner-pending-" + nonce
		f, err = dir.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer func() { _ = dir.Remove(temporary) }()
		_, err = f.Write(n.expected())
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err = dir.Link(temporary, marker); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err = syncDirectory(dir); err != nil {
			return err
		}
	}

	return n.verify(dir)
}
func (n Namespace) open() (*os.Root, error) {
	if !n.valid() {
		return nil, ErrOwnership
	}
	for _, p := range []string{n.Root, filepath.Join(n.Root, "datasets"), n.Directory()} {
		info, e := os.Lstat(p)
		if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return nil, ErrOwnership
		}
	}
	canonical, e := filepath.EvalSymlinks(n.Directory())
	if e != nil || canonical != n.Directory() {
		return nil, ErrOwnership
	}
	return os.OpenRoot(n.Directory())
}
func (n Namespace) verify(root *os.Root) error {
	info, e := root.Lstat(marker)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1024 {
		return ErrOwnership
	}
	f, e := root.Open(marker)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1025))
	if e != nil || !bytes.Equal(b, n.expected()) {
		return ErrOwnership
	}
	return nil
}
func (n Namespace) Verify() error {
	root, e := n.open()
	if e != nil {
		return e
	}
	defer root.Close()
	return n.verify(root)
}
func syncDirectory(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

// Inspect validates every directory entry before any removal. Arbitrary files,
// subdirectories and symlinks never authorize recursive deletion.
func (n Namespace) Inspect() (int64, int64, error) {
	root, e := n.open()
	if e != nil {
		return 0, 0, e
	}
	defer root.Close()
	if e = n.verify(root); e != nil {
		return 0, 0, e
	}
	names, size, e := inspect(root)
	return int64(len(names)), size, e
}
func inspect(root *os.Root) ([]string, int64, error) {
	f, e := root.Open(".")
	if e != nil {
		return nil, 0, e
	}
	defer f.Close()
	entries, e := f.ReadDir(maxEntries + 2)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, 0, e
	}
	if len(entries) > maxEntries+1 {
		return nil, 0, ErrOwnership
	}
	names := []string{}
	var size int64
	for _, x := range entries {
		if x.Name() == marker {
			continue
		}
		if !objectPattern.MatchString(x.Name()) && !pendingPattern.MatchString(x.Name()) && !ownerPendingPattern.MatchString(x.Name()) {
			return nil, 0, ErrOwnership
		}
		info, e := root.Lstat(x.Name())
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 256<<20 {
			return nil, 0, ErrOwnership
		}
		names = append(names, x.Name())
		size += info.Size()
	}
	return names, size, nil
}

// Clean removes only validated objects and interrupted archive temporaries.
// The ownership marker remains so a crash can resume with the same proof.
func (n Namespace) Clean(ctx context.Context) error {
	root, e := n.open()
	if e != nil {
		return e
	}
	defer root.Close()
	if e = n.verify(root); e != nil {
		return e
	}
	names, _, e := inspect(root)
	if e != nil {
		return e
	}
	for _, name := range names {
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = root.Remove(name); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	if e = syncDirectory(root); e != nil {
		return e
	}
	names, _, e = inspect(root)
	if e != nil {
		return e
	}
	if len(names) != 0 {
		return ErrOwnership
	}
	return n.verify(root)
}
