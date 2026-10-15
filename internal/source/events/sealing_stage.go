package events

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

var sealingStages = map[string]string{
	"callback": "scheduled ready",
	"work":     "offered interrupted accepted task_offered task_transferred task_abandoned finished abandoned producer_exited assembler_exited",
	"task":     "received duplicate cancel_seal skipped call_seal seal_returned abandoned exited pending_cleanup",
	"seal":     "mutex_acquired post_entered request_delivered post_returned commit_accepted commit_forwarded commit_discarded result_selected result_sent mutex_released",
	"assembly": "returned",
	"head":     "publisher_blocked publisher_accepted subscription_closed handled",
	"import":   "cancelled_result_ignored pending_task_missing known_result_ignored unknown_parent stored failed returned consumer_exited",
	"process":  "closing closed",
}

func sealingText(m map[string]json.RawMessage, key string) (string, bool) {
	var s string
	err := json.Unmarshal(m[key], &s)
	return s, err == nil
}
func sealingID(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	text := strings.TrimPrefix(s, prefix)
	n, err := strconv.ParseUint(text, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == text
}
func sealingDecimal(s string) bool {
	if len(s) == 0 || len(s) > 1024 || len(s) > 1 && s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// These are simulator actor observations. Keeping their source metadata does
// not turn them into consensus transitions or successful execution samples.
func sealingStageMetadata(m map[string]json.RawMessage, out map[string]any) {
	actor, ok := sealingText(m, "actor")
	if !ok {
		return
	}
	stage, ok := sealingText(m, "stage")
	if !ok || !slices.Contains(strings.Fields(sealingStages[actor]), stage) || stage == "" {
		return
	}
	out["actor"], out["stage"] = actor, stage
	for key, prefix := range map[string]string{"work_id": "work-", "commit_id": "commit-"} {
		if s, ok := sealingText(m, key); ok && sealingID(s, prefix) {
			out[key] = s
		}
	}
	for _, key := range []string{"request_height", "request_round"} {
		if s, ok := sealingText(m, key); ok && sealingDecimal(s) {
			out[key] = s
		}
	}
	if actor == "callback" {
		if s, ok := sealingText(m, "wait_ns"); ok {
			n, err := strconv.ParseUint(s, 10, 63)
			if err == nil && strconv.FormatUint(n, 10) == s {
				out["wait_ns"] = s
			}
		}
	}
	if actor == "work" {
		for key, allowed := range map[string]string{"interrupt": "none new_head resubmit", "outcome": "returned syncing missing_coinbase prepare_failed interrupted_new_head finalize_failed assembly_failed not_running terminal_difficulty"} {
			if s, ok := sealingText(m, key); ok && s != "" && slices.Contains(strings.Fields(allowed), s) {
				out[key] = s
			}
		}
	}
	if actor == "seal" {
		var cancelled bool
		if json.Unmarshal(m["cancelled"], &cancelled) == nil {
			out["cancelled"] = cancelled
		}
	}
	if actor == "process" && stage == "closed" {
		if s, ok := sealingText(m, "unjoined_seal_owner"); ok && (s == "" || sealingID(s, "work-")) {
			out["unjoined_seal_owner"] = s
		}
		if n, ok := policyCount(m, "pending_results", 0, 1024); ok {
			out["pending_results"] = n
		}
	}
}
