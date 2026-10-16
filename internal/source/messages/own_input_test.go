package messages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/0xmhha/wbft/codec"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadOwnInputProvenance(t *testing.T) {
	in := Input{ID: "native", Kind: "frames", Node: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", Path: "testdata/own-input-frames"}
	summary, err := Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var records []Record
	_, err = Read(context.Background(), Prepared{in, summary}, "7", genesis, func(r Record) error { records = append(records, r); return nil })
	if err != nil {
		t.Fatal("accepted own-input evidence not supported", err)
	}
	if len(records) != 4 || records[3].Type != "own_input" {
		t.Fatal("own-input source lost", records)
	}
	proof := records[1].OwnInput
	if proof == nil || proof.Outcome.Ordinal != 3 || proof.Input.Ordinal != 4 || proof.Outcome.Seq != "4" || proof.Input.Seq != "5" || proof.EngineRun != "1" || proof.Step != "7" || proof.Journal.Offset != "469" || records[1].RelayOf != "" || records[1].OwnMessageOf != "4" || records[2].InputOf != "5" {
		t.Fatal("wrong original references", records)
	}
	raw, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"payload":`) || strings.Contains(string(raw), `"signature":`) {
		t.Fatal("raw material crossed metadata boundary")
	}
}

func ownFixtureCopy(t *testing.T) Input {
	t.Helper()
	dir := t.TempDir()
	err := filepath.WalkDir("testdata/own-input-frames", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel("testdata/own-input-frames", p)
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
	return Input{ID: "native", Kind: "frames", Node: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", Path: dir}
}
func editOwnFrame(t *testing.T, in Input, change func(map[string]any) map[string]any) {
	t.Helper()
	p := filepath.Join(in.Path, "frames-own-fixture.jsonl")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var r map[string]any
		if err = json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		r = change(r)
		if r == nil {
			continue
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, append(b, '\n')...)
	}
	if err = os.WriteFile(p, out, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestOwnInputRejectsBeforeMetadataEmission(t *testing.T) {
	for _, name := range []string{"engine", "step", "peer", "input-kind", "via", "key", "phase", "payload", "missing-input", "missing-outcome", "wrong-reference", "null-reference", "both-sources", "non-relay", "unknown-generation", "position", "wrong-run", "loss", "bad-signature", "other-signer", "source-changed"} {
		t.Run(name, func(t *testing.T) {
			in := ownFixtureCopy(t)
			before, err := Fingerprint(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			editOwnFrame(t, in, func(r map[string]any) map[string]any {
				if r["type"] == "own_input" {
					switch name {
					case "engine":
						r["engine_run"] = 2
					case "step":
						r["step"] = 8
					case "peer":
						r["peer"] = "0xbb00000000000000000000000000000000000000"
					case "input-kind":
						r["input_kind"] = "start"
					case "via":
						r["via"] = "peer"
					case "key":
						r["dedup_key"] = "0x" + strings.Repeat("0", 64)
					case "phase":
						r["code"] = "0x14"
					case "payload":
						r["payload_sha256"] = strings.Repeat("0", 64)
					case "missing-input":
						return nil
					case "unknown-generation":
						r["engine_run"] = 0
					case "position":
						delete(r, "journal_offset")
					case "wrong-run":
						r["run"] = "another"
					}
				}
				if r["type"] == "outcome" {
					switch name {
					case "missing-outcome":
						return nil
					case "wrong-reference":
						r["input_of"] = 999
					}
				}
				if r["type"] == "frame" {
					switch name {
					case "null-reference":
						r["own_message_of"] = nil
					case "both-sources":
						r["relay_of"] = 9
					case "non-relay":
						r["cause"] = "broadcast"
					case "source-changed":
						r["t_mono_ns"] = 1
					}
				}

				if name == "other-signer" {
					r["node"] = "0xbb00000000000000000000000000000000000000"
					if r["type"] == "own_input" || r["type"] == "outcome" {
						r["peer"] = r["node"]
					}
				}
				return r
			})
			if name == "other-signer" {
				in.Node = "0xbb00000000000000000000000000000000000000"
			}
			if name == "bad-signature" {
				old := "7b92e6993235359c4e92009210267f4379285229645e446ccb1eae56c3b7cd1d"
				body, err := os.ReadFile(filepath.Join(in.Path, "payloads", old[:2], old))
				if err != nil {
					t.Fatal(err)
				}
				body[len(body)-1] = 9
				sum := sha256.Sum256(body)
				digest := hex.EncodeToString(sum[:])
				key := codec.DedupKey(body).Hex()
				if err = os.MkdirAll(filepath.Join(in.Path, "payloads", digest[:2]), 0700); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(in.Path, "payloads", digest[:2], digest), body, 0600); err != nil {
					t.Fatal(err)
				}
				editOwnFrame(t, in, func(r map[string]any) map[string]any {
					if r["type"] != "conn" {
						r["dedup_key"] = key
						if r["type"] != "outcome" {
							r["payload_sha256"] = digest
						}
					}
					return r
				})
			}
			if name == "loss" {
				p := filepath.Join(in.Path, "frames-own-fixture.jsonl")
				raw, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				line, err := json.Marshal(map[string]any{"v": 1, "type": "dropped", "node": in.Node, "run": "own-fixture", "seq": 9, "t_wall": "1970-01-01T00:00:00Z", "t_mono_ns": 0, "count": 1})
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(p, append(raw, append(line, '\n')...), 0600); err != nil {
					t.Fatal(err)
				}
			}
			summary, err := Fingerprint(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if name == "source-changed" {
				summary = before
			}
			emitted := 0
			_, err = Read(context.Background(), Prepared{in, summary}, "7", genesis, func(Record) error { emitted++; return nil })
			if err == nil || emitted != 0 {
				t.Fatal("invalid provenance reached metadata boundary", name, err, emitted)
			}
		})
	}
}

func TestOwnInputRetainsFullWidthReferences(t *testing.T) {
	in := ownFixtureCopy(t)
	const maximum = ^uint64(0)
	editOwnFrame(t, in, func(r map[string]any) map[string]any {
		switch r["type"] {
		case "outcome":
			r["seq"] = maximum - 1
			r["input_of"] = maximum
			r["engine_run"] = uint64(9007199254740993)
			r["step"] = maximum
		case "own_input":
			r["seq"] = maximum
			r["engine_run"] = uint64(9007199254740993)
			r["step"] = maximum
			r["journal_segment"] = maximum
			r["journal_offset"] = int64(9223372036854775807)
		case "frame":
			r["own_message_of"] = maximum - 1
		}
		return r
	})
	summary, err := Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var got *OwnInputEvidence
	_, err = Read(context.Background(), Prepared{in, summary}, "7", genesis, func(r Record) error {
		if r.Type == "frame" {
			got = r.OwnInput
		}
		return nil
	})
	if err != nil || got == nil || got.Input.Seq != "18446744073709551615" || got.Outcome.Seq != "18446744073709551614" || got.Input.Ordinal != 4 || got.EngineRun != "9007199254740993" || got.Step != "18446744073709551615" || got.Journal.Offset != "9223372036854775807" {
		t.Fatal("source coordinates truncated", err, got)
	}
}
func TestLegacyFrameReadablePrefixRemainsAvailable(t *testing.T) {
	in := writeFrames(t, []map[string]any{frame(1, vote(t, codec.CodePrepare))}, vote(t, codec.CodePrepare))
	summary, err := Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(in.Path, "frames-synthetic.jsonl")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString("{broken\n"); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	emitted := 0
	_, err = Read(context.Background(), Prepared{in, summary}, "7", genesis, func(Record) error { emitted++; return nil })
	if err == nil || emitted != 1 {
		t.Fatal("legacy prefix lost", err, emitted)
	}
}
