package messages

import (
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/journal"
)

type DeferredOrigin struct {
	WriterRun string `json:"writer_run"`
	CaptureID string `json:"capture_id"`
}

// DeferredEvidence describes the original capture independently of whether
// the inline input can be replayed. Its receipt clock belongs to Origin.
type DeferredEvidence struct {
	Origin      DeferredOrigin `json:"origin"`
	Status      string         `json:"status"`
	Reason      string         `json:"reason,omitempty"`
	ReceiptMono *string        `json:"receipt_mono_ns,omitempty"`
}

type ReceiveProfile struct {
	Version   string `json:"version"`
	Entries   string `json:"entries"`
	Bytes     string `json:"bytes"`
	PerPeer   string `json:"per_peer"`
	PerSource string `json:"per_source"`
}

// ProjectReceiveProfile projects validated limits into exact decimal metadata.
func ProjectReceiveProfile(o *journal.DeferredOptions) *ReceiveProfile {
	if o == nil {
		return nil
	}
	return &ReceiveProfile{Version: number(o.Profile), Entries: number(o.Entries), Bytes: number(o.Bytes), PerPeer: number(o.PerPeer), PerSource: number(o.PerSource)}
}

// ProjectDeferredEvidence admits only bounded identities and known source
// classifications. No inline payload or arbitrary resolver error is retained.
func ProjectDeferredEvidence(e *journal.DeferredEvidence) *DeferredEvidence {
	if e == nil {
		return nil
	}
	out := &DeferredEvidence{Origin: DeferredOrigin{CaptureID: "0"}, Status: "unavailable", Reason: "invalid_source"}
	if e.Origin.Run != "" && (!logs.Identifier(e.Origin.Run) || e.Origin.Capture == 0) {
		return out
	}
	out.Origin = DeferredOrigin{WriterRun: e.Origin.Run, CaptureID: strconv.FormatUint(e.Origin.Capture, 10)}
	if e.Status == "verified" && e.Origin.Run != "" && e.ReceiptMono != nil {
		mono, err := strconv.ParseInt(*e.ReceiptMono, 10, 64)
		if err == nil && mono >= 0 && strconv.FormatInt(mono, 10) == *e.ReceiptMono {
			value := *e.ReceiptMono
			out.Status, out.Reason, out.ReceiptMono = "verified", "", &value
		}
		return out
	}
	if e.Status == "unavailable" {
		switch e.Reason {
		case "missing_origin", "capture_resolver_unavailable", "missing_capture", "capture_unavailable", "capture_identity":
			out.Reason = e.Reason
		}
	}
	return out
}
