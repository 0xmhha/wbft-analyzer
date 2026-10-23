package events

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft/p2p/transport"
)

// TransportCacheDeclaration describes local runtime settings, not observed
// cache transitions, a resource bound, or remote delivery evidence.
type TransportCacheDeclaration struct {
	Profile string
	Active  bool
	Limits  transport.CachePolicyLimits
}

var transportCacheKeys = []string{"receive_pending", "receive_per_peer", "write_pending", "write_per_peer"}

func decodeTransportCache(m map[string]json.RawMessage) (*TransportCacheDeclaration, bool) {
	if len(m) != 3 || !policyString(m, "profile", transport.CachePolicyProfile) {
		return nil, false
	}
	var active *bool
	var limits map[string]json.RawMessage
	if json.Unmarshal(m["active"], &active) != nil || active == nil || json.Unmarshal(m["limits"], &limits) != nil || len(limits) != 4 {
		return nil, false
	}
	values := make([]uint64, 4)
	for i, key := range transportCacheKeys {
		var text string
		if json.Unmarshal(limits[key], &text) != nil {
			return nil, false
		}
		n, err := strconv.ParseUint(text, 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != text {
			return nil, false
		}
		values[i] = n
	}
	d := &TransportCacheDeclaration{Profile: transport.CachePolicyProfile, Active: *active,
		Limits: transport.CachePolicyLimits{ReceivePending: values[0], ReceivePerPeer: values[1], WritePending: values[2], WritePerPeer: values[3]}}
	return d, d.Limits.Validate() == nil
}

func flatTransportCache(m map[string]json.RawMessage) map[string]json.RawMessage {
	limits := map[string]json.RawMessage{}
	for _, key := range transportCacheKeys {
		limits[key] = m["transport_cache_"+key]
	}
	raw, err := json.Marshal(limits)
	if err != nil {
		return nil
	}
	return map[string]json.RawMessage{"profile": m["transport_cache_profile"], "active": m["transport_cache_active"], "limits": raw}
}

// TransportCacheFromMetadata rechecks only the closed flattened declaration.
func TransportCacheFromMetadata(fields map[string]any) (*TransportCacheDeclaration, bool) {
	m := map[string]json.RawMessage{}
	for _, key := range append([]string{"profile", "active"}, transportCacheKeys...) {
		name := "transport_cache_" + key
		if value, exists := fields[name]; exists {
			raw, err := json.Marshal(value)
			if err != nil {
				return nil, false
			}
			m[name] = raw
		}
	}
	return decodeTransportCache(flatTransportCache(m))
}

func transportCacheMetadata(m map[string]json.RawMessage, out map[string]any) {
	declared := false
	for key := range m {
		declared = declared || key == "transport_cache" || strings.HasPrefix(key, "transport_cache_")
	}
	if !declared {
		return
	}
	// Keep declaration presence through persistence even when its contents
	// cannot be interpreted. Never fall back to the legacy runtime model.
	out["transport_cache_profile"] = "unavailable"
	values := flatTransportCache(m)
	if raw, exists := m["transport_cache"]; exists {
		values = nil
		if json.Unmarshal(raw, &values) != nil {
			return
		}
	}
	d, ok := decodeTransportCache(values)
	if !ok {
		return
	}
	out["transport_cache_profile"], out["transport_cache_active"] = d.Profile, d.Active
	counts := []uint64{d.Limits.ReceivePending, d.Limits.ReceivePerPeer, d.Limits.WritePending, d.Limits.WritePerPeer}
	for i, key := range transportCacheKeys {
		out["transport_cache_"+key] = strconv.FormatUint(counts[i], 10)
	}
}
