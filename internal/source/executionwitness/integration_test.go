package executionwitness

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSyntheticExecutionHelperClosedInput(t *testing.T) {
	binary, dir := os.Getenv("WBFT_EXECUTION_TEST_HELPER"), os.Getenv("WBFT_EXECUTION_TEST_SOURCE")
	if binary == "" || dir == "" {
		t.Skip("synthetic helper integration inputs are not configured")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fingerprint, err := helperSHA(context.Background(), binary)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Load(context.Background(), raw, root, Helper{Path: binary, SHA256: fingerprint, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	source := bundle.Projection()
	if source.Verifier.SHA256 != fingerprint || source.Report.Protocol != Protocol || source.Report.Source.ChainID != "424242" || len(source.Report.Source.Blocks) != 1 || len(source.Report.Transactions) != 0 {
		t.Fatal("closed original source not verified")
	}
	if _, err := Load(context.Background(), raw, root, Helper{Path: binary, SHA256: fingerprint, Timeout: time.Nanosecond}); err == nil {
		t.Fatal("expired verification accepted")
	}
	transitions, err := LoadTransitions(context.Background(), raw, root, Helper{Path: binary, SHA256: fingerprint, Timeout: time.Minute})
	if err != nil {
		t.Fatal("closed transition source not verified", err)
	}
	projection := transitions.Projection()
	if projection.Verifier != source.Verifier || projection.Report.Protocol != TransitionProtocol || !reflect.DeepEqual(projection.Report.Execution, source.Report) || len(projection.Report.Blocks) != 1 || !projection.Report.Blocks[0].Genesis || len(projection.Report.Transactions) != 0 {
		t.Fatal("transition mode changed the execution report")
	}
	assertRefused := func(raw []byte, h Helper) {
		t.Helper()
		got, err := LoadTransitions(context.Background(), raw, root, h)
		if err == nil || got.Projection().Report.Protocol != "" {
			t.Fatal("unverified transition source admitted", err)
		}
	}
	operator := Helper{Path: binary, SHA256: fingerprint, Timeout: time.Minute}
	wrong := operator
	wrong.SHA256 = strings.Repeat("0", 64)
	assertRefused(raw, wrong)
	expired := operator
	expired.Timeout = time.Nanosecond
	assertRefused(raw, expired)
	var manifest map[string]any
	if json.Unmarshal(raw, &manifest) != nil {
		t.Fatal("decode synthetic manifest")
	}
	manifest["transitions"] = true
	modeRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	assertRefused(modeRaw, operator)
	delete(manifest, "transitions")
	blocks := manifest["blocks"].([]any)
	file := blocks[len(blocks)-1].(map[string]any)["file"].(map[string]any)
	file["sha256"] = strings.Repeat("0", 64)
	badChecksum, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	assertRefused(badChecksum, operator)
}
