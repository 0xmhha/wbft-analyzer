package messages

import (
	"reflect"
	"testing"

	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func ioFixture() []source.Record {
	a := source.Record{Input: "a", File: "f", Ordinal: 1, Seq: "1", Node: "a", Run: "r", Type: "frame", Dir: "out", Peer: "b", Key: "bytes", Phase: "COMMIT", Height: "2", Round: "0", Write: "ok", ClockSource: "recorded", Wall: "2020-01-01T00:00:00.020Z", IO: &source.IOInterval{StartWall: "2020-01-01T00:00:00Z", EndWall: "2020-01-01T00:00:00.010Z", StartMono: "0", EndMono: "10000000"}}
	b := a
	b.Input = "b"
	b.Node = "b"
	b.Peer = "a"
	b.Dir = "in"
	b.Wall = "2020-01-01T00:00:00.006Z"
	b.IO = &source.IOInterval{StartWall: "2019-12-31T23:59:59Z", EndWall: "2020-01-01T00:00:00.005Z", StartMono: "0", EndMono: "1005000000"}
	return []source.Record{a, b}
}

func TestIOProjectionKeepsCallbackNegativeAndDistinctMeasuredMetric(t *testing.T) {
	xs := ioFixture()
	original := append([]source.Record(nil), xs...)
	callback := PairEndpoints(ProjectRecords(xs).Endpoints, Clock{Model: "shared-host"})
	io := PairEndpoints(ProjectIORecords(xs).Endpoints, Clock{Model: "shared-host"})
	if len(callback) != 1 || len(io) != 1 || callback[0].Status != "negative" || io[0].Status != "valid" || io[0].Metric != WriteStartToReadComplete || *io[0].RawSeconds != .005 || callback[0].ID == io[0].ID {
		t.Fatal(callback, io)
	}
	if io[0].Send.Moment != "write_start" || io[0].Receive.Moment != "read_complete" || io[0].Send.CallbackWall != xs[0].Wall || io[0].Receive.CallbackWall != xs[1].Wall || io[0].Send.Ordinal != 1 {
		t.Fatal(io)
	}
	if !reflect.DeepEqual(xs, original) {
		t.Fatal("projection changed original records")
	}
	unknown := PairEndpoints(ProjectIORecords(xs).Endpoints, Clock{Model: "unknown"})
	if unknown[0].Status != "unknown_clock" || unknown[0].Seconds != nil {
		t.Fatal("IO manufactured clock agreement", unknown)
	}
}

func TestMissingIOCannotMakeRepeatedSendUnique(t *testing.T) {
	xs := ioFixture()
	repeat := xs[0]
	repeat.Ordinal = 2
	repeat.Seq = "2"
	repeat.IO = nil
	xs = append(xs, repeat)
	ps := PairEndpoints(ProjectIORecords(xs).Endpoints, Clock{Model: "shared-host"})
	if len(ps) != 1 || ps[0].Status != "ambiguous" || ps[0].SendCandidates != 2 {
		t.Fatal("unmeasured repeated copy disappeared", ps)
	}
	xs = ioFixture()
	xs[0].IO = nil
	ps = PairEndpoints(ProjectIORecords(xs).Endpoints, Clock{Model: "shared-host"})
	if len(ps) != 1 || ps[0].Status != "missing_clock" || ps[0].Seconds != nil || ps[0].Send.Wall != "" || ps[0].Send.CallbackWall == "" {
		t.Fatal("callback substituted for missing I/O", ps)
	}
}
