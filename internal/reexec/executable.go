package reexec

import (
	"context"
	"os"
	"path/filepath"
)

// ExecutableIdentity returns only bounded version identity and the file hash.
func ExecutableIdentity(path string) (string, string, error) {
	hash, err := binarySHA(path)
	return binaryVersion(path), hash, err
}

// SnapshotExecutable binds execution to immutable verified bytes, so a path
// replacement after registration cannot change the helper being launched.
func SnapshotExecutable(ctx context.Context, path, expectedSHA string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "wbft-timed-helper-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	target := filepath.Join(dir, "helper")
	if err = snapshotHelper(ctx, path, target, expectedSHA); err != nil {
		cleanup()
		return "", nil, err
	}
	return target, cleanup, nil
}

// SameExecutableVersion requires an exact known version alias.
func SameExecutableVersion(a, b string) bool { return sameVersion(a, b) }
