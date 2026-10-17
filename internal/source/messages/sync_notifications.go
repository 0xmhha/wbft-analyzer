package messages

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const syncNotificationsFormat = "wbft-sync-notifications/1"
const maxSyncNotifications = 1_000_000
const maxSyncNotificationLine = 64 * 1024

var errSyncNotifications = errors.New("invalid typed sync notification source")

// SyncNotificationsHeader reports the producer's live core identity. Its
// core_start_seq is not the sequence of this header or a notification.
type SyncNotificationsHeader struct {
	Format       string `json:"format"`
	Type         string `json:"type"`
	Node         string `json:"node"`
	Run          string `json:"run"`
	Validator    bool   `json:"validator"`
	CoreStartSeq string `json:"core_start_seq"`
}

// SyncNotification preserves the typed source's own sequence and available
// posting clock. The clock supplies no canonical or journal event boundary.
type SyncNotification struct {
	Type              string `json:"type"`
	Sequence          string `json:"sequence"`
	Kind              string `json:"kind"`
	PostedAtAvailable bool   `json:"posted_at_available"`
	PostedAt          string `json:"posted_at,omitempty"`
	Number            string `json:"number,omitempty"`
	Hash              string `json:"hash,omitempty"`
}

// SyncNotificationsFooter retains the original producer claims and counters.
// They do not independently authenticate the producer or decide a policy.
type SyncNotificationsFooter struct {
	Type              string `json:"type"`
	Observed          string `json:"observed"`
	Written           string `json:"written"`
	Dropped           string `json:"dropped"`
	Invalid           string `json:"invalid"`
	SequenceExhausted bool   `json:"sequence_exhausted"`
	CoreComplete      bool   `json:"core_complete"`
	CoreStopSeq       string `json:"core_stop_seq,omitempty"`
	ClosedNormally    bool   `json:"closed_normally"`
	Complete          bool   `json:"complete"`
}

type syncNotificationRow struct {
	notification SyncNotification
	ordinal      int64
}
type syncNotificationsFile struct {
	header           SyncNotificationsHeader
	notifications    []syncNotificationRow
	footer           *SyncNotificationsFooter
	footerOrdinal    int64
	lines            int64
	retainedComplete bool
	clockRegressions int64
}

// parseSyncNotifications validates before projection. Missing final records
// remain incomplete; malformed metadata is never emitted as a readable prefix.
func parseSyncNotifications(ctx context.Context, input io.Reader) (*syncNotificationsFile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source := &syncNotificationsFile{}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxSyncNotificationLine)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i+1], nil
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	var last uint64
	terminated := false
	var previousPosted time.Time
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		source.lines++
		raw := scanner.Bytes()
		terminated = len(raw) > 0 && raw[len(raw)-1] == '\n'
		if source.lines > maxSyncNotifications+2 || !utf8.Valid(raw) || !uniqueObject(raw) {
			return nil, errSyncNotifications
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return nil, errSyncNotifications
		}
		var kind string
		if json.Unmarshal(fields["type"], &kind) != nil || source.footer != nil {
			return nil, errSyncNotifications
		}
		switch kind {
		case "header":
			h := &source.header
			if source.lines != 1 || closedNotificationObject(raw, fields, h, []string{"format", "type", "node", "run", "validator", "core_start_seq"}, nil) != nil {
				return nil, errSyncNotifications
			}
			if h.Format != syncNotificationsFormat || !addressPattern.MatchString(h.Node) || strings.ToLower(h.Node) != h.Node || h.Run == "" || len(h.Run) > 128 || strings.IndexFunc(h.Run, unicode.IsControl) >= 0 || h.CoreStartSeq != "0" {
				return nil, errSyncNotifications
			}
		case "notification":
			if source.lines == 1 {
				return nil, errSyncNotifications
			}
			var n SyncNotification
			if closedNotificationObject(raw, fields, &n, []string{"type", "sequence", "kind", "posted_at_available"}, []string{"posted_at", "number", "hash"}) != nil {
				return nil, errSyncNotifications
			}
			seq, ok := cacheUint(n.Sequence)
			if !ok || seq == 0 || seq <= last {
				return nil, errSyncNotifications
			}
			last = seq
			_, hasTime := fields["posted_at"]
			_, hasNumber := fields["number"]
			_, hasHash := fields["hash"]
			if n.PostedAtAvailable != hasTime {
				return nil, errSyncNotifications
			}
			if hasTime {
				posted, err := time.Parse(time.RFC3339Nano, n.PostedAt)
				if err != nil || posted.IsZero() || posted.UTC().Format(time.RFC3339Nano) != n.PostedAt {
					return nil, errSyncNotifications
				}
				if !previousPosted.IsZero() && posted.Before(previousPosted) {
					source.clockRegressions++
				}
				previousPosted = posted
			}
			switch n.Kind {
			case "start", "failed":
				if hasNumber || hasHash {
					return nil, errSyncNotifications
				}
			case "done":
				number, ok := new(big.Int).SetString(n.Number, 10)
				if !hasNumber || !hasHash || !ok || number.Sign() < 0 || number.BitLen() > 256 || number.String() != n.Number || !hashPattern.MatchString(n.Hash) || strings.ToLower(n.Hash) != n.Hash {
					return nil, errSyncNotifications
				}
			default:
				return nil, errSyncNotifications
			}
			source.notifications = append(source.notifications, syncNotificationRow{n, source.lines})
		case "footer":
			if source.lines == 1 {
				return nil, errSyncNotifications
			}
			var footer SyncNotificationsFooter
			if closedNotificationObject(raw, fields, &footer, []string{"type", "observed", "written", "dropped", "invalid", "sequence_exhausted", "core_complete", "closed_normally", "complete"}, []string{"core_stop_seq"}) != nil {
				return nil, errSyncNotifications
			}
			observed, ok1 := cacheUint(footer.Observed)
			written, ok2 := cacheUint(footer.Written)
			dropped, ok3 := cacheUint(footer.Dropped)
			invalid, ok4 := cacheUint(footer.Invalid)
			if !ok1 || !ok2 || !ok3 || !ok4 || written != uint64(len(source.notifications)) || last > observed {
				return nil, errSyncNotifications
			}
			sum := new(big.Int).SetUint64(written)
			sum.Add(sum, new(big.Int).SetUint64(dropped))
			sum.Add(sum, new(big.Int).SetUint64(invalid))
			total := new(big.Int).SetUint64(observed)
			if (!footer.SequenceExhausted && sum.Cmp(total) != 0) || (footer.SequenceExhausted && (observed != math.MaxUint64 || sum.Cmp(total) < 0)) {
				return nil, errSyncNotifications
			}
			_, hasStop := fields["core_stop_seq"]
			stop, ok := cacheUint(footer.CoreStopSeq)
			if hasStop && (!ok || stop == 0) || footer.CoreComplete && !hasStop {
				return nil, errSyncNotifications
			}
			complete := footer.CoreComplete && footer.ClosedNormally && !footer.SequenceExhausted && dropped == 0 && invalid == 0
			if footer.Complete != complete {
				return nil, errSyncNotifications
			}
			if complete {
				for i, n := range source.notifications {
					if n.notification.Sequence != strconv.Itoa(i+1) {
						return nil, errSyncNotifications
					}
				}
			}
			source.footer = &footer
			source.footerOrdinal = source.lines
		default:
			return nil, errSyncNotifications
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if scanner.Err() != nil || source.lines == 0 {
		return nil, errSyncNotifications
	}
	source.retainedComplete = source.footer != nil && source.footer.Complete && terminated
	return source, nil
}

func closedNotificationObject(raw []byte, fields map[string]json.RawMessage, dst any, required, optional []string) error {
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
		if _, ok := fields[key]; !ok {
			return errSyncNotifications
		}
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key, value := range fields {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errSyncNotifications
		}
	}
	if json.Unmarshal(raw, dst) != nil {
		return errSyncNotifications
	}
	return nil
}
