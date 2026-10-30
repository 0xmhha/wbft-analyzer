package messages

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// Positive signatures use a public test scalar and the same declared chain.
// No message is delivered to a node or replayed under a foreign domain.
func TestJournalDomainOwnSignaturesBeforeAndAfterActivation(t *testing.T) {
	for _, activation := range []uint64{3, 100} {
		t.Run(fmt.Sprint(activation), func(t *testing.T) {
			cfgRaw := []byte(fmt.Sprintf(`{"chainId":7,"anzeon":{"wbft":{"requestTimeoutSeconds":1,"proposerPolicy":0}},"wbftRules":{"consensusRules":{"roundChangeDomain":%d}}}`, activation))
			config, err := types.ParseChainConfig(cfgRaw)
			if err != nil {
				t.Fatal(err)
			}
			genesisHash := types.Hash{1}
			domain, err := types.DomainForConfig(config, genesisHash)
			if err != nil {
				t.Fatal(err)
			}
			description, err := codec.EncodeRoundChangeDomain(domain)
			if err != nil {
				t.Fatal(err)
			}
			keyBytes := make([]byte, 32)
			keyBytes[31] = 1
			key, err := ecdsa.PrivateKeyFromBytes(keyBytes)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			node := ecdsa.Address(key)
			writer, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, journal.Identity{Run: "normal-domain", Self: node, ChainID: big.NewInt(7), GenesisHash: genesisHash, Core: journal.CoreOptions{ChainConfig: cfgRaw, DomainBytes: description}})
			if err != nil {
				t.Fatal(err)
			}
			var signer string
			for _, height := range []uint64{activation - 1, activation} {
				message := &codec.Message{Code: codec.CodeRoundChange, View: types.View{Sequence: types.HeightFromUint64(height), Round: types.RoundFromUint64(1)}}
				signing, err := codec.SigningPayloadWithDomain(message, domain)
				if err != nil {
					t.Fatal(err)
				}
				message.Signature, err = ecdsa.SignData(signing, key)
				if err != nil {
					t.Fatal(err)
				}
				recovered, err := ecdsa.RecoverDataSigner(signing, message.Signature)
				if err != nil {
					t.Fatal(err)
				}
				signer = strings.ToLower(recovered.Hex())
				payload, err := codec.EncodeMessage(message)
				if err != nil {
					t.Fatal(err)
				}
				writer.Put(journal.Record{Body: &journal.MsgRec{Dir: journal.Out, Code: uint64(codec.CodeRoundChange), Payload: payload, DedupKey: codec.DedupKey(payload), Write: "ok"}})
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			input := Input{ID: "normal", Kind: "journal", Node: strings.ToLower(node.Hex()), Path: dir}
			summary, err := Fingerprint(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			var frames []Record
			stats, err := Read(t.Context(), Prepared{Input: input, Summary: summary}, "7", genesisHash.Hex(), func(row Record) error {
				if row.Type == "frame" {
					frames = append(frames, row)
				}
				return nil
			})
			if err != nil || stats.Frames != 2 || len(frames) != 2 {
				t.Fatal(stats, err)
			}
			for _, row := range frames {
				if row.Signature != "recovered" || row.Signer != signer || row.SigningProfile == nil || row.SigningProfile.Activation != fmt.Sprint(activation) || len(row.SigningProfile.SHA256) != 64 {
					t.Fatal("lost bound signing context", row)
				}
			}
			_, meta, err := Prepare(t.Context(), Manifest{Format: Format, Name: "normal-domain", Network: logs.Network{ChainID: "7", GenesisHash: genesisHash.Hex()}, Clock: Clock{Model: "unknown"}, Inputs: []Input{input}})
			if err != nil {
				t.Fatal(err)
			}
			var marker struct {
				Normalizer string `json:"normalizer"`
				Signing    string `json:"signing_normalizer"`
			}
			if json.Unmarshal(meta, &marker) != nil || marker.Normalizer != Normalizer || marker.Signing != SigningNormalizer {
				t.Fatal("normalization cache lacks signing marker", string(meta))
			}
		})
	}
}
