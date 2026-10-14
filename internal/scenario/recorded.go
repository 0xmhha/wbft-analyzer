package scenario

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

func RecordedHash(heights []Height) string {
	raw, _ := json.Marshal(append([]Height{}, heights...))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ValidateRecorded binds the observed height series to its comparison scope
// and count. Missing per-height data remains unavailable, never invented.
func ValidateRecorded(heights []Height, counts []RoundCount, from, to uint64) error {
	if len(heights) == 0 {
		return nil
	}
	if from < 1 || to < from || to-from >= 10000 || len(heights) != int(to-from+1) || len(counts) != 1 {
		return errors.New("invalid recorded height scope")
	}
	late := int64(0)
	for i, h := range heights {
		if h.Number != from+uint64(i) || h.Time < h.PeriodSeconds || i > 0 && (h.Time < heights[i-1].Time || h.PeriodSeconds != h.Time-heights[i-1].Time) {
			return errors.New("invalid recorded header sequence")
		}
		if h.Round > 0 {
			late++
		}
	}
	if counts[0].Total != int64(len(heights)) || counts[0].Late != late {
		return errors.New("recorded count differs from height series")
	}
	return nil
}
