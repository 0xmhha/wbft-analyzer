package reconstruct

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft/types"
)

const syntheticGenesisConfig = `{"config":{"chainId":7,"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":10,"proposerPolicy":0}}},"alloc":{},"private_context":"NEVER_PROJECTED"}`

func TestReconstructionGenesisRetainsOnlyPinnedConfigurationIdentity(t *testing.T) {
	m := sourceManifest(t, "1", true)
	f := sourceFile(t, t.TempDir(), "local-genesis.json", []byte(syntheticGenesisConfig))
	m.Genesis = &f
	cfg, err := genesisConfig(t.Context(), m)
	if err != nil || cfg == nil || cfg.ChainID.String() != "7" || cfg.ConfigAt(types.HeightFromUint64(1)).RequestTimeoutMs != 2000 {
		t.Fatal(cfg, err)
	}
	a, err := Assess(t.Context(), m, "1", "1")
	if err != nil || a.Sources.GenesisSHA != f.SHA256 || a.CoreExecuted {
		t.Fatal(a, err)
	}
	encoded, _ := json.Marshal(a)
	if bytes.Contains(encoded, []byte("NEVER_PROJECTED")) || bytes.Contains(encoded, []byte(f.Path)) {
		t.Fatal("genesis document or path escaped")
	}
}

func TestReconstructionGenesisRefusesForeignOrAmbiguousConfiguration(t *testing.T) {
	for _, raw := range []string{
		strings.Replace(syntheticGenesisConfig, `"chainId":7`, `"chainId":8`, 1),
		strings.Replace(syntheticGenesisConfig, `"chainId":7`, `"chainId":7,"chainId":7`, 1),
		`{"alloc":{}}`,
		`{"config":{"chainId":7,"anzeon":{}}}`,
		strings.Replace(syntheticGenesisConfig, `,"proposerPolicy":0`, ``, 1),
	} {
		m := sourceManifest(t, "1", true)
		f := sourceFile(t, t.TempDir(), "local-genesis.json", []byte(raw))
		m.Genesis = &f
		if _, err := Assess(t.Context(), m, "1", "1"); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	f := newProcessingFixture(t, "1")
	genesis := sourceFile(t, t.TempDir(), "local-genesis.json", []byte(syntheticGenesisConfig))
	f.m.Genesis = &genesis
	f.m.Scopes[0].GenesisSHA = strings.Repeat("f", 64)
	if _, err := Assess(t.Context(), f.write(t), "1", "1"); err == nil {
		t.Fatal("scope accepted a different configuration identity")
	}
}

func TestReconstructionRetainsLegacyPolicyIdentity(t *testing.T) {
	m := sourceManifest(t, "1", true)
	raw := strings.Replace(syntheticGenesisConfig, `"proposerPolicy":0`, `"proposerPolicy":2`, 1)
	f := sourceFile(t, t.TempDir(), "local-genesis.json", []byte(raw))
	m.Genesis = &f
	cfg, err := genesisConfig(t.Context(), m)
	if err != nil || cfg.Base().ProposerPolicy.ID != 2 {
		t.Fatal("legacy source configuration was normalized", err)
	}
}
