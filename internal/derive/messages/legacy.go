package messages

import (
	"errors"
	"sort"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

type LegacyHeadAnchor struct {
	Height string `json:"height"`
	Hash   string `json:"hash"`
	Legacy Source `json:"legacy"`
	Native Source `json:"native"`
}
type LegacyAssociationProof struct {
	Address      string             `json:"address"`
	Node         string             `json:"node"`
	Input        string             `json:"input"`
	NativeInput  string             `json:"native_input"`
	SHA256       string             `json:"sha256"`
	NativeSHA256 string             `json:"native_sha256"`
	From         string             `json:"from_t"`
	To           string             `json:"to_t"`
	Status       string             `json:"status"`
	HeadAnchors  int64              `json:"head_anchors"`
	Records      int64              `json:"records"`
	Anchors      []LegacyHeadAnchor `json:"anchors"`
}

// DeclaredLegacyEvents validates explicit file scopes using recorded logger
// identity and at least two unique canonical head witnesses. It retains its
// declared evidence grade: matching heads are not native step or wire proof.
func DeclaredLegacyEvents(all, verified []logs.Event, declarations []logs.LegacyAssociation) ([]logs.Event, []LegacyAssociationProof, error) {
	out := []logs.Event{}
	proofs := []LegacyAssociationProof{}
	for _, d := range declarations {
		from, e1 := time.Parse(time.RFC3339Nano, d.From)
		to, e2 := time.Parse(time.RFC3339Nano, d.To)
		if e1 != nil || e2 != nil || !to.After(from) || to.Sub(from) > 24*time.Hour {
			return nil, nil, errors.New("invalid legacy association time bounds")
		}
		native := map[string][]logs.Event{}
		legacy := map[string][]logs.Event{}
		selected := []logs.Event{}
		self := false
		var node string
		within := func(e logs.Event) bool {
			t, err := time.Parse(time.RFC3339Nano, e.Wall)
			return err == nil && !t.Before(from) && !t.After(to)
		}
		for _, e := range verified {
			if e.Input == d.NativeInput && e.Record.Src == "event" && e.Record.Kind == event.NewHead && within(e) {
				number, hash := value(e, "number"), value(e, "hash")
				if number != "" && hash != "" {
					native[number] = append(native[number], e)
				}
			}
		}
		for _, e := range all {
			if e.Input != d.Input || e.Record.Src != "log" || !within(e) {
				continue
			}
			selected = append(selected, e)
			if node == "" {
				node = e.Node
			}
			if e.Node != node {
				return nil, nil, errors.New("legacy input has conflicting recording nodes")
			}
			if e.Record.Kind == event.Send || e.Record.Kind == event.MsgOutcome || e.Record.Kind == event.EngineStart {
				addr := value(e, "address")
				if addr != "" {
					if canonicalNode(addr) != canonicalNode(d.Address) {
						return nil, nil, errors.New("legacy logger identity conflicts with declared node")
					}
					self = true
				}
			}
			if e.Record.Kind == event.NewHead {
				number, hash := value(e, "number"), value(e, "hash")
				if number != "" && hash != "" {
					legacy[number] = append(legacy[number], e)
				}
			}
		}
		p := LegacyAssociationProof{Address: d.Address, Node: node, Input: d.Input, NativeInput: d.NativeInput, SHA256: d.SHA256, NativeSHA256: d.NativeSHA256, From: d.From, To: d.To, Status: "declared_head_anchors", Records: int64(len(selected)), Anchors: []LegacyHeadAnchor{}}
		keys := []string{}
		for height := range legacy {
			keys = append(keys, height)
		}
		sort.Strings(keys)
		for _, height := range keys {
			a, b := legacy[height], native[height]
			if len(b) == 0 {
				continue
			}
			if len(a) != 1 || len(b) != 1 || value(a[0], "hash") != value(b[0], "hash") {
				return nil, nil, errors.New("legacy/native head witness is conflicting or repeated")
			}
			p.HeadAnchors++
			if len(p.Anchors) < 16 {
				p.Anchors = append(p.Anchors, LegacyHeadAnchor{Height: height, Hash: value(a[0], "hash"), Legacy: eventSource(a[0]), Native: eventSource(b[0])})
			}
		}
		if !self || p.HeadAnchors < 2 {
			return nil, nil, errors.New("legacy declaration lacks logger identity or two head anchors")
		}
		// Every selected record stays in its original input/run namespace.
		out = append(out, selected...)
		proofs = append(proofs, p)
	}
	return out, proofs, nil
}
