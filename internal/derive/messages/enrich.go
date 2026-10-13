package messages

import source "github.com/0xmhha/wbft-analyzer/internal/source/messages"

// EnrichEvents supplies message fields from uniquely decoded identical bytes.
// It does not substitute a node's current view for the message's view, and a
// contradictory byte projection never becomes a plausible full-view match.
func EnrichEvents(xs []Endpoint, records []source.Record) []Endpoint {
	type fields struct{ phase, height, round, digest, author string }
	known := map[string]map[fields]bool{}
	for _, r := range records {
		if r.Type != "frame" || r.Decode != "decoded" || r.Key == "" {
			continue
		}
		if known[r.Key] == nil {
			known[r.Key] = map[fields]bool{}
		}
		known[r.Key][fields{r.Phase, r.Height, r.Round, r.Digest, r.Signer}] = true
	}
	out := append([]Endpoint(nil), xs...)
	for i, x := range out {
		if x.Key == "" || len(known[x.Key]) != 1 {
			continue
		}
		for f := range known[x.Key] {
			if f.phase != x.Phase {
				continue
			}
			if x.Height == "" && x.Round == "" {
				out[i].Height = f.height
				out[i].Round = f.round
			}
			if x.Digest == "" {
				out[i].Digest = f.digest
			}
			if x.Author == "" {
				out[i].Author = f.author
			}
		}
	}
	return out
}
