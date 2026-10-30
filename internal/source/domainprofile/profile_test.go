package domainprofile

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/codec/rlp"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

func declaration(t *testing.T, run string, activation uint64) *journal.SegmentRec {
	t.Helper()
	id := journal.Identity{Run: run, ChainID: big.NewInt(7), GenesisHash: types.Hash{1}}
	if activation != 0 {
		id.Core.ChainConfig = []byte(fmt.Sprintf(`{"chainId":7,"anzeon":{"wbft":{"requestTimeoutSeconds":1,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"roundChangeDomain":%d}}}`, activation))
		cfg, err := types.ParseChainConfig(id.Core.ChainConfig)
		if err != nil {
			t.Fatal(err)
		}
		domain, err := types.DomainForConfig(cfg, id.GenesisHash)
		if err != nil {
			t.Fatal(err)
		}
		id.Core.DomainBytes, err = codec.EncodeRoundChangeDomain(domain)
		if err != nil {
			t.Fatal(err)
		}
	}
	return &journal.SegmentRec{Identity: id}
}

// Negative models are detached unsigned declarations, never live traffic.
func TestDomainIdentityMissingFutureAndMalformed(t *testing.T) {
	for _, at := range []uint64{3, 100} {
		original := declaration(t, "A", at)
		domain, err := Segment(original)
		if err != nil || domain == nil || domain.Activation().String() != fmt.Sprint(at) {
			t.Fatal(domain, err)
		}
		for _, mode := range []string{"missing", "future", "malformed", "identity"} {
			var encodeErr error
			candidate := *original
			candidate.Core = original.Core.Copy()
			switch mode {
			case "missing":
				candidate.Core.DomainBytes = nil
			case "future":
				candidate.Core.DomainBytes, encodeErr = rlp.Encode([]any{uint64(2), big.NewInt(7), types.Hash{1}, new(big.Int).SetUint64(at)})
			case "malformed":
				candidate.Core.DomainBytes = []byte{0xc0}
			case "identity":
				candidate.GenesisHash = types.Hash{2}
			}
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			_, validationErr := Segment(&candidate)
			if mode == "missing" || mode == "future" {
				if !Unsupported(validationErr) {
					t.Fatal(mode, validationErr)
				}
			} else if !errors.Is(validationErr, ErrInvalid) || Unsupported(validationErr) {
				t.Fatal(mode, validationErr)
			}
		}
	}
	legacy := declaration(t, "legacy", 0)
	legacy.Core.ChainConfig = []byte("opaque legacy configuration")
	if domain, err := Segment(legacy); domain != nil || err != nil {
		t.Fatal("legacy exemption changed", err)
	}
}

func TestWriterReappearanceAndFiniteRegistry(t *testing.T) {
	var registry Registry
	for _, segment := range []*journal.SegmentRec{declaration(t, "A", 3), declaration(t, "B", 3), declaration(t, "A", 3)} {
		if _, err := registry.Observe(segment); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := registry.Observe(declaration(t, "A", 100)); !errors.Is(err, ErrInvalid) {
		t.Fatal("writer changed domain", err)
	}
	for _, cap := range []struct {
		count int
		bytes uint64
	}{{1, 1000}, {10, 34}} {
		var bounded Registry
		if _, err := bounded.observe(declaration(t, "A", 0), cap.count, cap.bytes); err != nil {
			t.Fatal(err)
		}
		if _, err := bounded.observe(declaration(t, "B", 0), cap.count, cap.bytes); err != nil || !bounded.exhausted || bounded.owners != nil {
			t.Fatal("legacy overflow retained index", err)
		}
		if _, err := bounded.observe(declaration(t, "C", 0), cap.count, cap.bytes); err != nil {
			t.Fatal(err)
		}
		if _, err := bounded.observe(declaration(t, "C", 3), cap.count, cap.bytes); !Unsupported(err) {
			t.Fatal("incomplete history granted selected profile", err)
		}
		var selected Registry
		if _, err := selected.observe(declaration(t, "A", 3), cap.count, cap.bytes); err != nil {
			t.Fatal(err)
		}
		if _, err := selected.observe(declaration(t, "B", 0), cap.count, cap.bytes); !Unsupported(err) {
			t.Fatal("selected index exceeded bound", err)
		}
	}
}
