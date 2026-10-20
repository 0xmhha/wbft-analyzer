package ingest

import (
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
	native "github.com/0xmhha/wbft/rpc"
)

func TestRecordedPolicyProfile(t *testing.T) {
	for _, test := range []struct {
		improvements []native.Improvement
		want         string
		fail         bool
	}{
		{},
		{improvements: []native.Improvement{{Name: "unrelated", Source: "profile"}}},
		{improvements: []native.Improvement{{Name: "checked_proposer_policy", Source: "profile"}}, want: journal.CheckedProposerPolicyProfile},
		{improvements: []native.Improvement{{Name: "checked_proposer_policy", Source: "chain"}}, fail: true},
		{improvements: []native.Improvement{{Name: "checked_proposer_policy", Source: "profile"}, {Name: "checked_proposer_policy", Source: "profile"}}, fail: true},
	} {
		got, err := recordedPolicyProfile(native.NodeInfo{Improvements: test.improvements})
		if got != test.want || (err != nil) != test.fail {
			t.Fatal(test, got, err)
		}
	}
}
