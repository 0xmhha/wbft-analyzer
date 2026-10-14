package reexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

var frameFile = regexp.MustCompile(`^frames-[A-Za-z0-9._-]+\.jsonl$`)
var frameObject = regexp.MustCompile(`^payloads/[0-9a-f]{2}/[0-9a-f]{64}$`)

// SnapshotFrames reconstructs exact exported frame files and payload objects.
// A digest in an exported line without retained bytes stays unproved.
func SnapshotFrames(ctx context.Context, summary messages.Summary, refs []messages.ArchivedFile) (string, error) {
	if summary.Kind != "frames" || len(refs) == 0 || len(refs) != len(summary.Files) {
		return "", errors.New("frame references unavailable")
	}
	byName := map[string]messages.ArchivedFile{}
	for _, ref := range refs {
		if _, exists := byName[ref.Name]; exists {
			return "", errors.New("duplicate frame reference")
		}
		byName[ref.Name] = ref
	}
	dir, err := os.MkdirTemp("", "wbft-frame-snapshot-")
	if err != nil {
		return "", err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(dir)
		}
	}()
	var total int64
	for _, file := range summary.Files {
		ref, exists := byName[file.Name]
		valid := frameFile.MatchString(file.Name) || frameObject.MatchString(file.Name) && strings.Split(file.Name, "/")[1] == filepath.Base(file.Name)[:2]
		if !exists || !valid || file.Bytes < 0 || file.Bytes > 256<<20 || total > 16<<30-file.Bytes || ref.Bytes != file.Bytes || ref.SHA256 != file.SHA256 || filepath.Base(ref.Path) != file.SHA256 {
			return "", errors.New("frame reference mismatch")
		}
		total += file.Bytes
		target := filepath.Join(dir, file.Name)
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return "", err
		}
		if err = copyVerified(ctx, ref.Path, target, file.Bytes, file.SHA256); err != nil {
			return "", err
		}
	}
	actual, err := messages.Fingerprint(ctx, messages.Input{ID: summary.ID, Kind: "frames", Node: summary.Node, Path: dir})
	if err != nil || actual.SHA256 != summary.SHA256 {
		return "", errors.New("frame snapshot fingerprint mismatch")
	}
	success = true
	return dir, nil
}
