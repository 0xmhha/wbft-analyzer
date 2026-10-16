package messages

import "testing"

func TestCacheSuppressionInheritedClockIsNotAMeasurement(t *testing.T) {
	rows := cacheFixtureRows(t)
	rows[5]["t_wall"] = "2026-01-02T03:04:05.000000123Z"
	rows[5]["t_mono_ns"] = 42
	result, err := readCacheFixture(t, rows)
	if err != nil || len(result) != len(rows) {
		t.Fatalf("valid suppression with inherited timestamps rejected: %v (records %d)", err, len(result))
	}
	suppressed := result[5]
	if suppressed.ClockSource != "unavailable" || suppressed.Mono != nil || suppressed.Wall != "" {
		t.Fatal("inherited suppression timestamps became a measured clock", suppressed)
	}
	if suppressed.Ordinal != 6 || suppressed.Seq != "6" || suppressed.CacheEvidence == nil || suppressed.CacheEvidence.Operation.Ordinal != 5 {
		t.Fatal("suppression lost its exact original source or decision", suppressed)
	}
	if result[6].Write != "ok" || result[6].Mono == nil || *result[6].Mono != "3" || result[6].CacheEvidence == nil || result[6].CacheEvidence.Operation.Ordinal != 4 {
		t.Fatal("independent physical callback changed", result[6])
	}
}

func TestCacheSuppressionClockClaimsRemainAtomic(t *testing.T) {
	for _, name := range []string{"recorded", "inherited", "missing", "negative"} {
		t.Run(name, func(t *testing.T) {
			rows := cacheFixtureRows(t)
			rows[5]["t_wall"] = "2026-01-02T03:04:05Z"
			rows[5]["t_mono_ns"] = 42
			switch name {
			case "recorded", "inherited":
				rows[5]["clock_source"] = name
			case "missing":
				delete(rows[5], "clock_source")
			case "negative":
				rows[5]["t_mono_ns"] = -1
			}
			result, err := readCacheFixture(t, rows)
			if err == nil || len(result) != 0 {
				t.Fatalf("invalid clock claim emitted records: %v (%d)", err, len(result))
			}
		})
	}
}

func TestCacheDeclarationsStillRejectInheritedClocks(t *testing.T) {
	for _, index := range []int{0, 2} {
		rows := cacheFixtureRows(t)
		rows[index]["t_wall"] = "2026-01-02T03:04:05Z"
		rows[index]["t_mono_ns"] = 42
		result, err := readCacheFixture(t, rows)
		if err == nil || len(result) != 0 {
			t.Fatalf("declaration with inherited clock emitted records: %v (%d)", err, len(result))
		}
	}
}
