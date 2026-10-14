package scenario

import (
	"testing"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
)

func TestWireMetricSelectionNeverMixesMeasurementsOrInventsCoverage(t *testing.T) {
	callback := pairs.Pair{ID: "callback", Metric: "link", Sender: "a", Receiver: "b", Strength: "link", Status: "negative", Write: "ok", SendCandidates: 1, ReceiveCandidates: 1, Send: &pairs.Source{Node: "a", Wall: "2020-01-01T00:00:00.020Z"}, Receive: &pairs.Source{Node: "b", Wall: "2020-01-01T00:00:00.006Z"}}
	io := callback
	io.ID = "io"
	io.Metric = pairs.WriteStartToReadComplete
	io.Status = "valid"
	io.Send = &pairs.Source{Node: "a", Moment: "write_start", Wall: "2020-01-01T00:00:00Z"}
	io.Receive = &pairs.Source{Node: "b", Moment: "read_complete", Wall: "2020-01-01T00:00:00.005Z"}
	old, e := FitLinks([]string{"a", "b"}, []pairs.Pair{callback, io}, nil, "shared-host", 0)
	if e != nil || old[0].Observed != 0 || old[0].Unproved != 1 {
		t.Fatal(old, e)
	}
	got, e := FitLinksMetric([]string{"a", "b"}, []pairs.Pair{callback, io}, nil, "shared-host", 0, pairs.WriteStartToReadComplete)
	if e != nil || got[0].Metric != pairs.WriteStartToReadComplete || got[0].Observed != 1 || got[0].Delays[0].Nanoseconds != 5000000 || got[0].Loss != nil || got[0].Status != "partial" {
		t.Fatal(got, e)
	}
	io.Send.Moment = "callback"
	got, e = FitLinksMetric([]string{"a", "b"}, []pairs.Pair{io}, nil, "shared-host", 0, pairs.WriteStartToReadComplete)
	if e != nil || got[0].Observed != 0 {
		t.Fatal("wrong measurement boundary accepted", got, e)
	}
	if _, e := FitLinksMetric([]string{"a", "b"}, nil, nil, "shared-host", 0, "corrected"); e == nil {
		t.Fatal("unsupported measurement accepted")
	}
}
