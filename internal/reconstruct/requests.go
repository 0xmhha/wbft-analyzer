package reconstruct

import (
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
)

// ProposalRequestWitness binds a recorded request to an explicitly logged
// own proposal source. It does not establish a complete input stream or
// substitute the canonical block for an unrecorded builder request.
type ProposalRequestWitness struct {
	Height         string               `json:"height"`
	Round          string               `json:"round"`
	Request        Point                `json:"request"`
	Status         string               `json:"status"`
	PayloadCount   int64                `json:"proposal_payload_count"`
	BodySource     *ProcessingCandidate `json:"body_source,omitempty"`
	MessageHandler *Point               `json:"message_handler,omitempty"`
	CoreInputReady bool                 `json:"core_input_ready"`
}

type proposalRequest struct {
	witness     ProposalRequestWitness
	wall        time.Time
	valid       bool
	payload     *logs.PayloadWitness
	point       Point
	close       Point
	payloadWall time.Time
}

func (p *processingCollector) requestLog(e logs.Event, boundary bool, payload *logs.PayloadWitness) error {
	if boundary && p.pendingRequest >= 0 {
		p.requests[p.pendingRequest].close = logPoint(e)
		p.pendingRequest = -1
	}
	if e.Record.Kind == event.BuildRequest {
		if e.Record.View == nil {
			p.unlocatedRequests++
			return nil
		}
		v := e.Record.View
		if _, ok := p.index[v.Seq]; !ok {
			return nil
		}
		if err := p.reserve(); err != nil {
			return err
		}
		wall, _ := time.Parse(time.RFC3339Nano, e.Wall)
		p.requests = append(p.requests, proposalRequest{
			witness: ProposalRequestWitness{Height: v.Seq, Round: v.Round, Request: logPoint(e), Status: "body_unavailable"},
			wall:    wall,
			valid:   !e.ViewInferred && field(e, "address") == p.node && v.Round != "",
		})
		p.pendingRequest = len(p.requests) - 1
	}
	if payload != nil && payload.Phase == "PRE-PREPARE" && p.pendingRequest >= 0 {
		// Contradictory payload views still count against the shared bound
		// when they are selected as a request's possible body source.
		height := payload.Height
		if height == "" && e.Record.View != nil {
			height = e.Record.View.Seq
		}
		if _, selected := p.index[height]; !selected {
			if err := p.reserve(); err != nil {
				return err
			}
		}
		r := &p.requests[p.pendingRequest]
		r.witness.PayloadCount++
		r.payload, r.point = payload, logPoint(e)
		r.payloadWall, _ = time.Parse(time.RFC3339Nano, e.Wall)
	}
	return nil
}

type logPosition struct {
	run  string
	line int64
}

func (p *processingCollector) finishRequests(m Manifest, out *Assessment) {
	out.Sources.UnlocatedRequests = p.unlocatedRequests
	handlers := map[logPosition]ProcessingWitness{}
	for _, height := range out.Heights {
		for _, w := range height.Processing {
			handlers[logPosition{w.Handler.Run, w.Handler.Line}] = w
		}
	}
	scopes := map[string]RunScope{}
	for _, s := range m.Scopes {
		scopes[s.LogRun] = s
	}
	for _, r := range p.requests {
		v := r.witness
		switch {
		case !r.valid:
			v.Status = "invalid_context"
		case v.PayloadCount > 1:
			v.Status = "ambiguous_proposal_source"
		case v.PayloadCount == 0:
			// A request may have been stored without broadcasting. A later
			// canonical or received proposal is not its builder input.
		case r.payload.Status != "decoded" || r.payload.Height != v.Height || r.payload.Round != v.Round || r.payload.Signer != p.node || v.Round != "0" || !r.payloadWall.After(r.wall):
			v.Status = "invalid_proposal_source"
		default:
			v.Status = "unbound_message"
			h, ok := handlers[logPosition{r.close.Run, r.close.Line}]
			if ok && h.Phase == "PRE-PREPARE" && h.Height == v.Height && h.Round == v.Round && h.Signer == p.node && h.CandidateCount == 1 && h.Candidates[0].Source == r.point {
				v.Status = h.Status
				if h.Status == "linked" {
					scope, declared := scopes[v.Request.Run]
					if !declared || !acceptanceInScope(scope, r.wall) {
						v.Status = "outside_scope"
					} else {
						v.Status = "linked_proposal_source"
						candidate, handler := h.Candidates[0], h.Handler
						v.BodySource, v.MessageHandler = &candidate, &handler
					}
				}
			}
		}
		out.Heights[p.index[v.Height]].Requests = append(out.Heights[p.index[v.Height]].Requests, v)
	}
}
