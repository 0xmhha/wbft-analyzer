package messages

import "testing"

func TestSeriesRetainsMissingBucketsAndOriginalQuantiles(t *testing.T) {
	a, b := 1.0, 10.0
	pairs := []Pair{{At: "2020-01-01T00:00:00.000000001Z", Height: "18446744073709551617", Round: "0", Sender: "a", Receiver: "b", Phase: "PREPARE", Strength: "node", Path: "propagation_processing", Metric: "propagation_processing", Clock: "shared-host", Status: "valid", Seconds: &a}, {At: "2020-01-01T00:00:02Z", Height: "18446744073709551617", Round: "0", Sender: "a", Receiver: "b", Phase: "PREPARE", Strength: "node", Path: "propagation_processing", Metric: "broadcast_to_receipt", Clock: "unknown", Status: "unknown_clock", RawSeconds: &b}}
	result := Series(pairs, 1)
	if len(result.Points) != 2 || result.Points[0].Height != "18446744073709551617" || result.Points[1].At != "2020-01-01T00:00:02Z" {
		t.Fatal(result)
	}
	for _, g := range result.Points[1].Groups {
		if g.Distribution.P95 != nil {
			t.Fatal("unknown trend became valid", g)
		}
	}
}
