package executionwitness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Helper struct {
	Path    string
	SHA256  string
	Timeout time.Duration
	WorkDir string
}

const MaxHelperBytes = 512 << 20

func helperSHA(ctx context.Context, name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", ErrSource
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxHelperBytes {
		return "", ErrSource
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxHelperBytes+1))
	if err != nil || ctx.Err() != nil || n != info.Size() {
		return "", ErrSource
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func snapshotHelper(ctx context.Context, source, target, expected string) (Origin, error) {
	if !hash(expected, 32) {
		return Origin{}, ErrSource
	}
	f, err := os.Open(source)
	if err != nil {
		return Origin{}, ErrSource
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxHelperBytes {
		return Origin{}, ErrSource
	}
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return Origin{}, ErrSource
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(f, MaxHelperBytes+1))
	closeErr := out.Close()
	if err != nil || closeErr != nil || n != info.Size() || ctx.Err() != nil || hex.EncodeToString(h.Sum(nil)) != expected {
		return Origin{}, ErrSource
	}
	data, err := buildinfo.ReadFile(target)
	if err != nil || data.Main.Path != "github.com/0xmhha/wbft-analyzer/tools/execution-witness" || !strings.HasPrefix(data.GoVersion, "go1.26.") {
		return Origin{}, ErrSource
	}
	for _, d := range data.Deps {
		if d.Path == "github.com/ethereum/go-ethereum" && d.Replace != nil && d.Replace.Path == OriginPath && d.Replace.Version == OriginVersion && d.Replace.Sum == OriginSum {
			return Origin{Path: OriginPath, Version: OriginVersion, Sum: OriginSum}, nil
		}
	}
	return Origin{}, ErrSource
}

// loadHelper executes only the operator-selected binary whose fingerprint is passed
// separately from the untrusted source manifest. Files and executable are copied
// to an isolated directory and rechecked before constructing the opaque bundle.
func loadHelper(ctx context.Context, raw []byte, root *os.Root, h Helper, transitions bool, consume func([]byte, snapshot, Origin) error) error {
	if root == nil || ctx.Err() != nil || !hash(h.SHA256, 32) || h.Timeout <= 0 || h.Timeout > 30*time.Minute {
		return ErrSource
	}
	raw = bytes.Clone(raw)
	dir, err := os.MkdirTemp(h.WorkDir, "wbft-execution-witness-")
	if err != nil {
		return ErrSource
	}
	defer os.RemoveAll(dir)
	sources := filepath.Join(dir, "sources")
	if os.Mkdir(sources, 0700) != nil {
		return ErrSource
	}
	s, err := prepare(ctx, raw, root, sources)
	if err != nil {
		return ErrSource
	}
	path, err := filepath.Abs(h.Path)
	if err != nil {
		return ErrSource
	}
	binary := filepath.Join(dir, "helper")
	origin, err := snapshotHelper(ctx, path, binary, h.SHA256)
	if err != nil {
		return ErrSource
	}
	manifest := filepath.Join(dir, "manifest.json")
	if os.WriteFile(manifest, raw, 0400) != nil {
		return ErrSource
	}
	child, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	args := []string{"--manifest", manifest, "--root", sources}
	if transitions {
		args = append(args, "--transitions")
	}
	cmd := exec.CommandContext(child, binary, args...)
	cmd.Dir = dir
	cmd.Env = []string{"GOMAXPROCS=2", "GOTOOLCHAIN=local", "TMPDIR=" + dir}
	cmd.WaitDelay = time.Second
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ErrSource
	}
	if cmd.Start() != nil {
		return ErrSource
	}
	waited := false
	defer func() {
		cancel()
		_ = stdout.Close()
		if !waited {
			_ = cmd.Wait()
		}
	}()
	output, readErr := io.ReadAll(io.LimitReader(stdout, MaxProjectionBytes+1))
	if readErr != nil || len(output) > MaxProjectionBytes {
		cancel()
	}
	waitErr := cmd.Wait()
	waited = true
	if readErr != nil || waitErr != nil || child.Err() != nil || len(output) > MaxProjectionBytes {
		return ErrSource
	}
	if consume(output, s, origin) != nil {
		return ErrSource
	}
	actual, err := helperSHA(ctx, binary)
	if err != nil || actual != h.SHA256 {
		return ErrSource
	}
	actual, err = helperSHA(ctx, path)
	if err != nil || actual != h.SHA256 {
		return ErrSource
	}
	copied, err := os.ReadFile(manifest)
	if err != nil || !bytes.Equal(copied, raw) || s.recheck(ctx, root, sources) != nil {
		return ErrSource
	}
	return nil
}

// Load admits only the execution protocol. Mode selection is compiled into
// the loader entry point, outside both the manifest and public HTTP input.
func Load(ctx context.Context, raw []byte, root *os.Root, h Helper) (Bundle, error) {
	var projection Projection
	err := loadHelper(ctx, raw, root, h, false, func(output []byte, s snapshot, origin Origin) error {
		var report Report
		if exactJSON(output, MaxProjectionBytes, &report) != nil || validate(report, s, origin) != nil {
			return ErrSource
		}
		projection = Projection{Report: report, Verifier: Verifier{SHA256: h.SHA256, Origin: origin}}
		return nil
	})
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{value: projection}, nil
}
