package ingest

import (
	"errors"

	"github.com/0xmhha/wbft/observe/journal"
	native "github.com/0xmhha/wbft/rpc"
)

// recordedPolicyProfile uses only the node's explicit declaration. A source
// version or an absent declaration never assigns new defaults to old captures.
func recordedPolicyProfile(node native.NodeInfo) (string, error) {
	profile := ""
	for _, improvement := range node.Improvements {
		if improvement.Name != "checked_proposer_policy" {
			continue
		}
		if improvement.Source != "profile" || profile != "" {
			return "", errors.New("ambiguous proposer policy declaration")
		}
		profile = journal.CheckedProposerPolicyProfile
	}
	return profile, nil
}
