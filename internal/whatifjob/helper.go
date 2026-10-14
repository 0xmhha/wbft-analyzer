package whatifjob

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/whatif"
)

func runHelper(ctx context.Context, h reexec.Helper, journal, chain string, policy whatif.Policy, output io.Writer) error {
	if h.ExpectedSHA == "" || h.Timeout <= 0 || h.Timeout > 30*time.Minute {
		return whatif.ErrEvidence
	}
	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	path, cleanup, err := reexec.SnapshotExecutable(ctx, h.Path, h.ExpectedSHA)
	if err != nil {
		return err
	}
	defer cleanup()
	cmd := exec.CommandContext(ctx, path, h.Args...)
	cmd.WaitDelay = time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return err
	}
	waited := false
	defer func() {
		_ = stdin.Close()
		cancel()
		if !waited {
			_ = cmd.Wait()
		}
	}()
	scanner := bufio.NewScanner(io.LimitReader(stdout, (64<<20)+1))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	enc := json.NewEncoder(stdin)
	if err = enc.Encode(map[string]any{"type": "hello", "protocol": reexec.Protocol}); err != nil {
		return err
	}
	var hello struct {
		Type, Protocol, Impl, Version string
		Features                      []string
	}
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &hello) != nil || hello.Type != "hello" || hello.Protocol != reexec.Protocol || hello.Impl != "wbft" {
		return whatif.ErrEvidence
	}
	actualVersion, _, err := reexec.ExecutableIdentity(path)
	if err != nil || !reexec.SameExecutableVersion(hello.Version, actualVersion) {
		return whatif.ErrEvidence
	}
	capabilities := map[string]bool{}
	for _, feature := range hello.Features {
		capabilities[feature] = true
	}
	if !capabilities["timed_inputs_v1"] || !capabilities["timed_state_v1"] || !capabilities["timed_actions_v1"] || !capabilities["context_answers_v1"] {
		return whatif.ErrEvidence
	}
	if err = enc.Encode(map[string]any{"type": "timed_replay", "id": 1, "journal": journal, "chain": chain, "answer_scope": "context", "timer_policy": policy}); err != nil {
		return err
	}
	terminal := false
	for scanner.Scan() {
		if terminal {
			return whatif.ErrEvidence
		}
		var header struct {
			Type string `json:"type"`
			ID   uint64 `json:"id"`
		}
		if json.Unmarshal(scanner.Bytes(), &header) != nil || header.ID != 1 {
			return whatif.ErrEvidence
		}
		switch header.Type {
		case "timed_step":
		case "timed_done", "error":
			terminal = true
		default:
			return whatif.ErrEvidence
		}
		if _, err = output.Write(append(append([]byte(nil), scanner.Bytes()...), '\n')); err != nil {
			return err
		}
		if terminal {
			if err = enc.Encode(map[string]any{"type": "bye"}); err != nil {
				return err
			}
			_ = stdin.Close()
		}
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	if !terminal {
		return whatif.ErrEvidence
	}
	err = cmd.Wait()
	waited = true
	return err
}
