package messages

import (
	"context"
	"encoding/json"
	"io"
	"os"
)

// SyncNotificationSource retains an original header or footer. It does not
// assign a source sequence to either record or reinterpret a core cursor.
type SyncNotificationSource struct {
	Format string                   `json:"format"`
	Stage  string                   `json:"stage"`
	Header *SyncNotificationsHeader `json:"header,omitempty"`
	Footer *SyncNotificationsFooter `json:"footer,omitempty"`
}

// SyncNotificationEvidence points only within the same original typed file.
// RetainedComplete concerns that file, independently of producer authentication,
// canonical lifecycle validation or a consensus-policy verdict.
type SyncNotificationEvidence struct {
	Header           OwnSourcePoint  `json:"header"`
	Footer           *OwnSourcePoint `json:"footer,omitempty"`
	RetainedComplete bool            `json:"retained_complete"`
}

func readSyncNotifications(ctx context.Context, p Prepared, emit func(Record) error) (stats Stats, err error) {
	stats.ClockDiagnostics = "downloader_posted_sequence"
	if p.Input.Kind != "sync_notifications" || p.Input.ID != p.Summary.ID || p.Summary.Kind != p.Input.Kind {
		return stats, errSyncNotifications
	}
	root, err := os.OpenRoot(p.Input.Path)
	if err != nil {
		return stats, errSyncNotifications
	}
	defer root.Close()
	spool, err := os.CreateTemp("", "wbft-sync-notifications-*")
	if err != nil {
		return stats, errSyncNotifications
	}
	defer func() { _ = spool.Close(); _ = os.Remove(spool.Name()) }()
	encoder := json.NewEncoder(spool)
	runs := map[string]bool{}
	for _, file := range p.Summary.Files {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		if !syncNotificationName.MatchString(file.Name) {
			return stats, errSyncNotifications
		}
		reader, err := root.Open(file.Name)
		if err != nil {
			return stats, errSyncNotifications
		}
		source, err := parseSyncNotifications(ctx, reader)
		closeErr := reader.Close()
		if err != nil {
			return stats, err
		}
		if closeErr != nil {
			return stats, errSyncNotifications
		}
		if source.header.Node != p.Summary.Node || runs[source.header.Run] || stats.Records+source.lines > maxSyncNotifications+2 {
			return stats, errSyncNotifications
		}
		runs[source.header.Run] = true
		proof := &SyncNotificationEvidence{Header: OwnSourcePoint{Input: p.Input.ID, File: file.Name, Ordinal: 1, Seq: ""}, RetainedComplete: source.retainedComplete}
		if source.footer != nil {
			proof.Footer = &OwnSourcePoint{Input: p.Input.ID, File: file.Name, Ordinal: source.footerOrdinal, Seq: ""}
		}
		record := func(ordinal int64) Record {
			return Record{Input: p.Input.ID, File: file.Name, Ordinal: ordinal, Node: source.header.Node, Run: source.header.Run, ClockSource: "unavailable", NotificationEvidence: proof}
		}
		header := record(1)
		header.Type = "sync_notification_source"
		header.NotificationSource = &SyncNotificationSource{Format: syncNotificationsFormat, Stage: "header", Header: &source.header}
		if encoder.Encode(header) != nil {
			return stats, errSyncNotifications
		}
		for _, row := range source.notifications {
			value := row.notification
			r := record(row.ordinal)
			r.Type = "sync_notification"
			r.Seq = value.Sequence
			r.Notification = &value
			if value.PostedAtAvailable {
				r.ClockSource = "downloader_posted"
				r.Wall = value.PostedAt
			}
			if encoder.Encode(r) != nil {
				return stats, errSyncNotifications
			}
		}
		if source.footer != nil {
			footer := record(source.footerOrdinal)
			footer.Type = "sync_notification_source"
			footer.NotificationSource = &SyncNotificationSource{Format: syncNotificationsFormat, Stage: "footer", Footer: source.footer}
			if encoder.Encode(footer) != nil {
				return stats, errSyncNotifications
			}
		}
		stats.Records += source.lines
		stats.ClockRegressions += source.clockRegressions
		if !source.retainedComplete {
			stats.PartialRuns++
		}
	}
	if len(runs) == 0 {
		return stats, errSyncNotifications
	}
	// Match the immutable prepared files before exposing any normalized row.
	after, err := Fingerprint(ctx, p.Input)
	if err != nil || after.SHA256 != p.Summary.SHA256 {
		return stats, errSyncNotifications
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return stats, errSyncNotifications
	}
	decoder := json.NewDecoder(spool)
	for {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		var r Record
		err := decoder.Decode(&r)
		if err == io.EOF {
			return stats, nil
		}
		if err != nil {
			return stats, errSyncNotifications
		}
		if err := emit(r); err != nil {
			return stats, err
		}
	}
}
