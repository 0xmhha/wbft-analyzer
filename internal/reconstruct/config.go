package reconstruct

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	"github.com/0xmhha/wbft/types"
)

func genesisConfig(ctx context.Context, m Manifest) (*types.Config, error) {
	if m.Genesis == nil {
		return nil, nil
	}
	raw, err := snapshot(ctx, *m.Genesis, 16<<20)
	if err != nil {
		return nil, err
	}
	var document struct {
		Config json.RawMessage `json:"config"`
	}
	failure := errors.New("reconstruction genesis configuration refused")
	if jsonmeta.Decode(raw, 16<<20, false, &document) != nil || len(document.Config) == 0 {
		return nil, failure
	}
	cfg, err := types.ParseChainConfig(document.Config)
	if err != nil || cfg.ChainID == nil || cfg.ChainID.String() != m.Network.ChainID || cfg.CheckTransitions() != nil || cfg.CheckProposerPolicy() != nil {
		return nil, failure
	}
	return cfg, nil
}
