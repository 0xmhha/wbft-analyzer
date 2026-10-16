package ingest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestOwnInputProductionIngestAndInvalidRecordRefusal(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "invalid"}[invalid], func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			dir := t.TempDir()
			fixture := "../source/messages/testdata/own-input-frames"
			err := filepath.WalkDir(fixture, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(fixture, p)
				if err != nil {
					return err
				}
				if d.IsDir() {
					return os.MkdirAll(filepath.Join(dir, rel), 0700)
				}
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(dir, rel), b, 0600)
			})
			if err != nil {
				t.Fatal(err)
			}
			if invalid {
				p := filepath.Join(dir, "frames-own-fixture.jsonl")
				raw, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				var changed []byte
				for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
					var r map[string]any
					if err = json.Unmarshal([]byte(line), &r); err != nil {
						t.Fatal(err)
					}
					if r["type"] == "own_input" {
						r["engine_run"] = 2
					}
					b, err := json.Marshal(r)
					if err != nil {
						t.Fatal(err)
					}
					changed = append(changed, append(b, '\n')...)
				}
				if err = os.WriteFile(p, changed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			manifest := messages.Manifest{Format: messages.Format, Name: "synthetic-own-input", Network: logs.Network{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, Clock: messages.Clock{Model: "unknown"}, Inputs: []messages.Input{{ID: "native", Kind: "frames", Node: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", Path: dir}}}
			archive := filepath.Join(t.TempDir(), "retained")
			result, err := MessagesWithInputs(ctx, s, manifest, archive)
			records, readErr := s.MessageRecords(ctx, result.DatasetID, store.MessageFilter{Limit: 20})
			if readErr != nil {
				t.Fatal(readErr)
			}
			if invalid {
				if err == nil || result.Records != 0 || len(records) != 0 {
					t.Fatal("invalid provenance stored records", err, result, records)
				}
				return
			}
			if err != nil || result.Records != 4 || len(records) != 4 {
				t.Fatal(result, err, records)
			}
			own := 0
			for _, r := range records {
				if r.OwnInput != nil {
					own++
					for _, point := range []messages.OwnSourcePoint{r.OwnInput.Input, r.OwnInput.Outcome} {
						original, err := s.MessageRecordAt(ctx, result.DatasetID, point.Input, point.File, point.Ordinal)
						if err != nil || original.Seq != point.Seq {
							t.Fatal(point, original, err)
						}
					}
				}
			}
			if own != 3 {
				t.Fatal("own source chain lost", records)
			}
			again, err := MessagesWithInputs(ctx, s, manifest, archive)
			if err != nil || !again.Skipped || again.DatasetID != result.DatasetID {
				t.Fatal("repeat changed input identity", again, err)
			}
		})
	}
}
