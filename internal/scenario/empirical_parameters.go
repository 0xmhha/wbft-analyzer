package scenario

import (
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
)

// empiricalParametersVerified checks the WBFT scalar schedule only. Contract
// execution is replaced by recorded epoch candidates in the empirical model;
// it remains unproved in the independent physical runtime assessment.
func empiricalParametersVerified(binding RuntimeBinding) bool {
	if binding.Configuration != "startup_scalars_verified" || !binding.CaptureComplete {
		return false
	}
	for _, reason := range binding.Unavailable {
		if reason != "later_configuration_unproved" {
			return false
		}
	}
	var parameters *[6]string
	valid := func(point runtimeobs.Point) bool {
		c := point.Config
		if c == nil || c.Transitions != "0" || !strings.EqualFold(c.Address, binding.Source.Node) {
			return false
		}
		n, err := strconv.ParseUint(c.SystemContractUpgrades, 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != c.SystemContractUpgrades {
			return false
		}
		scalars := [6]string{c.RequestTimeoutMS, c.BlockPeriodSeconds, c.Epoch, c.AllowedFutureBlockSeconds, c.MaxRequestTimeoutSeconds, c.ProposerPolicy}
		if parameters != nil && *parameters != scalars {
			return false
		}
		parameters = &scalars
		return true
	}
	if len(binding.Configurations) > 0 {
		for _, snapshot := range binding.Configurations {
			if snapshot.State != "observed" || snapshot.Comparison != "startup_scalars_verified" || !valid(snapshot.Point) {
				return false
			}
		}
		return true
	}
	return len(binding.Startups) == 1 && valid(binding.Startups[0])
}
