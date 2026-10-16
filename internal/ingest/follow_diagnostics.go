package ingest

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

// FollowDiagnostic contains only fixed labels and bounded protocol codes.
// Underlying errors may contain credentials and must not become log messages.
type FollowDiagnostic struct {
	Stage string
	Kind  string
	Code  string
}

type followFailure struct {
	stage string
	err   error
}

func (e *followFailure) Error() string { return "follow collection failed" }
func (e *followFailure) Unwrap() error { return e.err }

// FollowFailure preserves errors.Is/As behavior for retry/fatal decisions while
// exposing bounded diagnostics for collection failures. It never formats err.
func FollowFailure(err error) FollowDiagnostic {
	out := FollowDiagnostic{}
	if err == nil {
		return out
	}
	var failure *followFailure
	if errors.As(err, &failure) {
		switch failure.stage {
		case "open_source", "read_cursor", "read_head", "read_genesis", "read_current_header",
			"read_parent_header", "prefetch_headers", "read_first_header", "validate_heights",
			"read_last_header", "capture_observations", "normalize_observations",
			"validate_observations", "ingest_headers", "encode_observations", "ingest_observations", "commit_cursor":
			out.Stage = failure.stage
		}
	}
	out.Kind = "unknown"
	switch {
	case errors.Is(err, ErrFollowIdentity):
		out.Kind = "identity"
	case errors.Is(err, ErrFollowIncomplete):
		out.Kind = "participation"
	case errors.Is(err, store.ErrFollowCursor):
		out.Kind = "cursor"
	case errors.Is(err, context.Canceled):
		out.Kind = "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		out.Kind = "deadline"
	default:
		var server *rpc.Error
		var database *pgconn.PgError
		var network net.Error
		switch {
		case errors.As(err, &server):
			out.Kind = "rpc"
			if int64(server.Code) >= -2147483648 && int64(server.Code) <= 2147483647 {
				out.Code = strconv.Itoa(server.Code)
			}
		case errors.As(err, &database):
			out.Kind = "database"
			if validSQLState(database.Code) {
				out.Code = database.Code
			}
		case errors.As(err, &network):
			out.Kind = "network"
		}
	}
	return out
}

func validSQLState(code string) bool {
	if len(code) != 5 {
		return false
	}
	for _, c := range code {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}
