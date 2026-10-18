package executionwitness

import (
	"context"
	"os"
	"path/filepath"
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
}
