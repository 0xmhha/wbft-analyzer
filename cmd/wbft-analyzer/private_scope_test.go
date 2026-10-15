package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Exercise a real overlay-built binary in its own PostgreSQL schema. Synthetic
// identities are test fixtures and do not expand the stock binary's trust set.
func TestPrivateOverlayStorageAndExport(t *testing.T) {
	dsn := os.Getenv("WBFT_ANALYZER_TEST_DSN")
	if dsn == "" {
		t.Skip("WBFT_ANALYZER_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	var random [6]byte
	if _, err = rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	schema := "private_" + hex.EncodeToString(random[:])
	if _, err = conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	privateDSN := u.String()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		p := filepath.Join(temporary, name)
		if e := os.WriteFile(p, data, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	original, err := os.ReadFile(filepath.Join(root, "cmd/wbft-analyzer/main.go"))
	if err != nil {
		t.Fatal(err)
	}
	mainOverlay := write("main.go", bytes.Replace(original, []byte(`"fmt"`), []byte(`"fmt"
 _ "github.com/0xmhha/wbft-analyzer/internal/withheld"`), 1))
	extension := write("register.go", []byte(`package withheld
import (
 "strings"
 "github.com/0xmhha/wbft-analyzer/internal/privacy"
)
func init() {
 if err:=privacy.RegisterExtension(privacy.Extension{Build:"operator",Requirements:[]string{"WBFT-SM-999","WBFT-SM-083"},Catalogs:[]string{strings.Repeat("a",64)}});err!=nil{panic(err)}
}
`))
	overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(root, "cmd/wbft-analyzer/main.go"): mainOverlay, filepath.Join(root, "internal/withheld/register.go"): extension}})
	overlayPath := write("overlay.json", overlay)
	binary := filepath.Join(temporary, "private")
	build := exec.CommandContext(ctx, "go", "build", "-overlay", overlayPath, "-o", binary, "./cmd/wbft-analyzer")
	build.Dir = root
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("overlay build: %v\n%s", e, out)
	}
	command := func(want int, args ...string) string {
		t.Helper()
		c := exec.CommandContext(ctx, binary, args...)
		out, e := c.CombinedOutput()
		code := 0
		if e != nil {
			if exit, ok := e.(*exec.ExitError); ok {
				code = exit.ExitCode()
			} else {
				t.Fatal(e)
			}
		}
		if code != want {
			t.Fatalf("private command %v: code %d, %s", args, code, out)
		}
		return string(out)
	}
	sample, err := os.ReadFile(filepath.Join(root, "internal/reports/testdata/report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err = json.Unmarshal(sample, &report); err != nil {
		t.Fatal(err)
	}
	runMeta := report["run"].(map[string]any)
	inspector := runMeta["inspector"].(map[string]any)
	runMeta["network"] = map[string]any{"chain_id": "17", "genesis_hash": "private-test", "name": "private test"}
	inspector["build"] = "operator"
	inspector["catalog_sha256"] = strings.Repeat("a", 64)
	report["results"] = []any{map[string]any{"requirement": "WBFT-SM-999", "verdict": "CANNOT_DECIDE"}}
	report["observations"] = []any{}
	raw, _ := json.Marshal(report)
	file := write("report.json", raw)
	command(exitOK, "ingest", "reports", "--db", privateDSN, file)
	hash := sha256.Sum256(raw)
	sum := hex.EncodeToString(hash[:])
	name := "report:" + sum
	var privateNetworks, privateDatasets, reports int
	if err = conn.QueryRow(ctx, "SELECT (SELECT count(*) FROM "+schema+".networks WHERE visibility='private'),(SELECT count(*) FROM "+schema+".datasets WHERE visibility='private'),(SELECT count(*) FROM "+schema+".reports WHERE inspector_build='operator')").Scan(&privateNetworks, &privateDatasets, &reports); err != nil {
		t.Fatal(err)
	}
	if privateNetworks != 1 || privateDatasets != 1 || reports != 1 {
		t.Fatal("private classification was lost")
	}
	publicOut := filepath.Join(temporary, "public-export")
	refused := command(exitDataErr, "export", "--db", privateDSN, "--dataset", name, "--out", publicOut, "--target", "public")
	if strings.Contains(refused, "WBFT-SM-999") {
		t.Fatal("refusal disclosed requirement")
	}
	if _, err = os.Stat(publicOut); !os.IsNotExist(err) {
		t.Fatal("refusal wrote output")
	}
	privateOut := filepath.Join(temporary, "private-export")
	command(exitOK, "export", "--db", privateDSN, "--dataset", name, "--out", privateOut)
	if _, err = os.Stat(filepath.Join(privateOut, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"export", "--db", privateDSN, "--dataset", name, "--out", publicOut}, &stdout, &stderr); code != exitUnavailable || !strings.Contains(stderr.String(), "visibility") {
		t.Fatalf("stock build opened private store: %d %s", code, stderr.String())
	}
	// Public profile checks remain closed even inside a private deployment.
	inspector["build"] = "public"
	inspector["catalog_sha256"] = "7e2a9c6ba7c8a148f062c79d54d0e28049323bcfb170871c9e494463f2c5cc87"
	raw, _ = json.Marshal(report)
	file = write("cross-profile.json", raw)
	refused = command(exitDataErr, "ingest", "reports", "--db", privateDSN, file)
	if strings.Contains(refused, "WBFT-SM-999") {
		t.Fatal("profile refusal disclosed requirement")
	}
	inspector["build"] = "operator"
	raw, _ = json.Marshal(report)
	file = write("cross-catalog.json", raw)
	command(exitDataErr, "ingest", "reports", "--db", privateDSN, file)
	var count int
	if err = conn.QueryRow(ctx, "SELECT count(*) FROM "+schema+".reports").Scan(&count); err != nil || count != 1 {
		t.Fatal("refused report left rows", count, err)
	}
}
