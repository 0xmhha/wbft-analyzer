package messages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFramePayloadOriginDoesNotProveSuccessfulTransmission(t *testing.T) {
	payload := []byte{0xc0}
	hash := sha256.Sum256(payload)
	digest := hex.EncodeToString(hash[:])
	size := uint64(len(payload))
	for _, tc := range []struct {
		name, value, kind, dir, write string
		valid                         bool
	}{
		{"old_absence", "", "frame", "out", "ok", true},
		{"consumed", `"consumed"`, "frame", "out", "ok", true},
		{"consumed_error", `"consumed"`, "frame", "out", "error", true},
		{"read", `"consumed"`, "frame", "in", "", true},
		{"failed_write_snapshot", `"provided_reader_snapshot"`, "frame", "out", "error", true},
		{"success_snapshot", `"provided_reader_snapshot"`, "frame", "out", "ok", false},
		{"unknown_write_snapshot", `"provided_reader_snapshot"`, "frame", "out", "no_error_recorded", false},
		{"unattempted_snapshot", `"provided_reader_snapshot"`, "frame", "out", "not_attached", false},
		{"read_snapshot", `"provided_reader_snapshot"`, "frame", "in", "", false},
		{"misplaced", `"consumed"`, "conn", "out", "ok", false},
		{"unknown", `"received"`, "frame", "out", "error", false},
		{"null", `null`, "frame", "out", "error", false},
		{"boolean", `true`, "frame", "out", "error", false},
		{"empty", `""`, "frame", "out", "error", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := frameRecord{Type: tc.kind, Dir: tc.dir, Payload: digest, Size: &size, PayloadSource: json.RawMessage(tc.value)}
			_, err := framePayloadSource(x, tc.write)
			if (err == nil) != tc.valid {
				t.Fatal(err)
			}
			if tc.value != "" {
				x.Payload = ""
				if _, err := framePayloadSource(x, tc.write); err == nil {
					t.Fatal("payload origin without payload evidence accepted")
				}
			}
		})
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "payloads", digest[:2]), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payloads", digest[:2], digest), payload, 0600); err != nil {
		t.Fatal(err)
	}
	raw := `{"v":1,"type":"frame","node":"` + self + `","run":"synthetic","seq":0,"t_wall":"2020-01-01T00:00:00Z","t_mono_ns":0,"dir":"out","code":"0x13","size":1,"payload_sha256":"` + digest + `","payload_source":"provided_reader_snapshot","write_result":"error"}`
	if err := os.WriteFile(filepath.Join(dir, "frames-synthetic.jsonl"), []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	in := Input{ID: "frames", Kind: "frames", Node: self, Path: dir}
	summary, err := Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var rows []Record
	_, err = Read(context.Background(), Prepared{Input: in, Summary: summary}, "7", genesis, func(r Record) error { rows = append(rows, r); return nil })
	if err != nil || len(rows) != 1 || rows[0].PayloadSource != "provided_reader_snapshot" || rows[0].Write != "error" || rows[0].PayloadSHA256 != digest || rows[0].Ordinal != 1 {
		t.Fatal(rows, err)
	}
	encoded, err := json.Marshal(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	var restored Record
	if err := json.Unmarshal(encoded, &restored); err != nil || restored.PayloadSource != rows[0].PayloadSource || restored.Write != "error" {
		t.Fatal("payload origin lost across persistence", restored, err)
	}
}
