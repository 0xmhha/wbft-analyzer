package executionwitness

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

func TestUntrustedJSONCannotConstructVerifiedBundle(t *testing.T) {
	var b Bundle
	if err := json.Unmarshal([]byte(`{"report":{"protocol":"wbft-execution-witness/1"},"verifier":{"sha256":"claimed"}}`), &b); !errors.Is(err, ErrSource) {
		t.Fatal("untrusted JSON was not refused", err)
	}
	if b.Projection().Report.Protocol != "" {
		t.Fatal("report created a verified bundle")
	}
	original := Bundle{value: Projection{Report: Report{Protocol: Protocol, Source: Snapshot{Blocks: []BlockEvidence{{Hash: "retained"}}}, Transactions: []Transaction{{Frames: []Frame{{Path: []uint32{1, 2}}}}}}}}
	copy := original.Projection()
	copy.Report.Source.Blocks[0].Hash = "changed"
	copy.Report.Transactions[0].Frames[0].Path[0] = 9
	again := original.Projection()
	if again.Report.Source.Blocks[0].Hash != "retained" || again.Report.Transactions[0].Frames[0].Path[0] != 1 {
		t.Fatal("projection mutated authenticated evidence")
	}
}
func TestOperatorFingerprintCannotComeFromManifest(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw := []byte(`{"format":"wbft-execution-witness-input/1","node":"0x1111111111111111111111111111111111111111","helper":"untrusted","genesis":{"path":"missing","sha256":"unknown"},"blocks":[]}`)
	if _, err := Load(context.Background(), raw, root, Helper{Path: "untrusted", Timeout: time.Second}); err == nil {
		t.Fatal("missing operator fingerprint accepted")
	}
	if _, err := prepare(context.Background(), raw, root, dir); err == nil {
		t.Fatal("manifest helper selection accepted")
	}
	if _, err := snapshotHelper(context.Background(), filepath.Join(dir, "missing"), filepath.Join(dir, "copy"), strings.Repeat("0", 64)); err == nil {
		t.Fatal("missing binary accepted")
	}
}
func TestSourceDigestAndRootPolicies(t *testing.T) {
	dir := t.TempDir()
	data := []byte("closed input")
	if os.WriteFile(filepath.Join(dir, "source"), data, 0600) != nil {
		t.Fatal("write source")
	}
	if os.Symlink("source", filepath.Join(dir, "link")) != nil {
		t.Fatal("create source alias")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	input := FileInput{Path: "source", SHA256: digest(data).SHA256}
	if _, err := readOriginal(context.Background(), root, input, len(data)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"..", "../source", "source/../source", "/source", "link"} {
		bad := input
		bad.Path = name
		if _, err := readOriginal(context.Background(), root, bad, MaxReadBytes); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	if _, err := readOriginal(context.Background(), root, input, len(data)-1); err == nil {
		t.Fatal("read budget ignored")
	}
	if os.WriteFile(filepath.Join(dir, "source"), []byte("changed"), 0600) != nil {
		t.Fatal("change input")
	}
	if _, err := readOriginal(context.Background(), root, input, MaxReadBytes); err == nil {
		t.Fatal("changed input accepted")
	}
}
func TestNamedErrorRequiresMatchingRoleRuntimeAndReturnDigest(t *testing.T) {
	returned := keccak.Sum256Bytes([]byte("InvalidProposal()"))[:4]
	f := Frame{Path: []uint32{}, Kind: "CALL", From: "0x1111111111111111111111111111111111111111", To: "0x2222222222222222222222222222222222222222", Input: digest(nil), Return: digest(returned), Gas: "1000", GasUsed: "10", Status: "reverted", VMError: "execution_reverted", AccountCodeHash: validatorCodeHash, AccountCodeBytes: 10, Authority: "gov_validator", AuthorityIndex: "0", ABIStatus: "decoded_revert", ErrorName: "InvalidProposal", Observation: "call_hook"}
	if !validFrame(f, "1") {
		t.Fatal("valid error refused")
	}
	for _, alter := range []func(*Frame){func(f *Frame) { f.AccountCodeHash = "0x" + strings.Repeat("0", 64) }, func(f *Frame) { f.Authority = "other" }, func(f *Frame) { f.Return = digest([]byte{1, 2, 3, 4}) }, func(f *Frame) { f.AuthorityIndex = "1" }, func(f *Frame) { f.ErrorName = "arbitrary detail" }} {
		copy := f
		alter(&copy)
		if validFrame(copy, "1") {
			t.Fatal("unbound error accepted")
		}
	}
	f.AccountCodeHash = councilCodeHash
	f.Authority = "gov_council"
	f.ErrorName = "InvalidValidator"
	f.Return = digest(keccak.Sum256Bytes([]byte("InvalidValidator()"))[:4])
	if validFrame(f, "1") {
		t.Fatal("validator error attributed to council runtime")
	}
}

func TestSnapshotGasBudgetIncludesEveryNonGenesisBlock(t *testing.T) {
	for _, test := range []struct {
		name   string
		last   uint64
		refuse bool
	}{{"exact cumulative limit", 0, false}, {"later block exceeds cumulative limit", 1, true}} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			out := t.TempDir()
			put := func(name string, raw []byte) FileInput {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
				return FileInput{Path: name, SHA256: digest(raw).SHA256}
			}
			manifest := Manifest{Format: InputFormat, Node: "0x1111111111111111111111111111111111111111", Genesis: put("genesis.json", []byte(`{"config":{"chainId":7}}`))}
			var previous types.Hash
			for i, gas := range []uint64{MaxTotalGas, MaxTotalGas, test.last} {
				header := &types.Header{Number: types.HeightFromUint64(uint64(i)), ParentHash: previous, Difficulty: big.NewInt(0), GasLimit: MaxBlockGas, GasUsed: gas, UncleHash: keccak.Sum256([]byte{0xc0})}
				raw, err := codec.EncodeBlock(&types.Block{Header: header, Body: []rlp.RawValue{{0xc0}, {0xc0}}})
				if err != nil {
					t.Fatal(err)
				}
				previous = codec.BlockHash(header)
				manifest.Blocks = append(manifest.Blocks, BlockInput{Index: strconv.Itoa(i), File: put(strconv.Itoa(i)+".rlp", raw)})
			}
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			_, err = prepare(context.Background(), raw, root, out)
			if (err != nil) != test.refuse {
				t.Fatal("cumulative gas accounting differs", err)
			}
		})
	}
}

func TestSnapshotRejectsUncommittedWBFTUncleBody(t *testing.T) {
	for _, test := range []struct {
		name              string
		body              rlp.RawValue
		validRoot, refuse bool
	}{
		{"committed empty body", rlp.RawValue{0xc0}, true, false},
		{"nonempty uncommitted body", rlp.RawValue{0xc1, 0x80}, true, true},
		{"incorrect empty root", rlp.RawValue{0xc0}, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir, out := t.TempDir(), t.TempDir()
			put := func(name string, raw []byte) FileInput {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
				return FileInput{Path: name, SHA256: digest(raw).SHA256}
			}
			h := &types.Header{Number: types.HeightFromUint64(0), Difficulty: big.NewInt(0), GasLimit: 1000000}
			if test.validRoot {
				h.UncleHash = keccak.Sum256([]byte{0xc0})
			}
			encoded, err := codec.EncodeBlock(&types.Block{Header: h, Body: []rlp.RawValue{{0xc0}, test.body}})
			if err != nil {
				t.Fatal(err)
			}
			manifest := Manifest{Format: InputFormat, Node: "0x1111111111111111111111111111111111111111", Genesis: put("genesis.json", []byte(`{"config":{"chainId":7}}`)), Blocks: []BlockInput{{Index: "0", File: put("block.rlp", encoded)}}}
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			_, err = prepare(context.Background(), raw, root, out)
			if (err != nil) != test.refuse {
				t.Fatal("uncommitted uncle body/root boundary differs", err)
			}
		})
	}
}
