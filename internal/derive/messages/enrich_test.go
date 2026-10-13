package messages

import (
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"testing"
)

func TestEnrichmentNeverChoosesContradictoryDecodedBytes(t *testing.T) {
	x := endpoint("send", "a", "b", "", "bytes", 0)
	x.Round = ""
	x.Digest = ""
	x.Strength = "node"
	records := []source.Record{{Type: "frame", Decode: "decoded", Key: "bytes", Phase: "PREPARE", Height: "18446744073709551617", Round: "0", Digest: "d", Signer: "a"}}
	y := EnrichEvents([]Endpoint{x}, records)[0]
	if y.Height != "18446744073709551617" || y.Author != "a" {
		t.Fatal(y)
	}
	conflict := records[0]
	conflict.Height = "1"
	records = append(records, conflict)
	y = EnrichEvents([]Endpoint{x}, records)[0]
	if y.Height != "" || y.Digest != "" {
		t.Fatal("conflicting bytes supplied a view", y)
	}
}
