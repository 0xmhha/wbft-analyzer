package messages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/0xmhha/wbft/observe/journal"
)

// SelectedPayload reads only an immutable prepared input, never a request path.
// Its metadata must exactly reproduce the saved row before bytes are exposed
// to the caller's official frame and signature checks. Bytes stay local.
func SelectedPayload(ctx context.Context, p Prepared, row Record, chain, genesis string) ([]byte, uint64, error) {
	failure := errors.New("selected message source unavailable")
	if row.Type != "frame" || row.Dir != "in" || row.Decode != "decoded" || row.Signature != "recovered" || row.PeerStatus != "recorded" || row.Input != p.Summary.ID || row.Node != p.Summary.Node {
		return nil, 0, failure
	}
	before, err := Fingerprint(ctx, p.Input)
	if err != nil || before.SHA256 != p.Summary.SHA256 {
		return nil, 0, failure
	}
	matched := 0
	_, err = Read(ctx, p, chain, genesis, func(actual Record) error {
		if actual.File == row.File && actual.Ordinal == row.Ordinal {
			if !reflect.DeepEqual(actual, row) {
				return failure
			}
			matched++
		}
		return nil
	})
	if err != nil || matched != 1 {
		return nil, 0, failure
	}
	var payload []byte
	var code uint64
	switch p.Input.Kind {
	case "journal":
		reader, e := journal.OpenReader(nil, p.Input.Path)
		if e != nil {
			return nil, 0, failure
		}
		for ordinal := int64(1); ordinal <= row.Ordinal; ordinal++ {
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
			record, position, e := reader.NextAt()
			if e != nil {
				return nil, 0, failure
			}
			if ordinal == row.Ordinal {
				message, ok := record.Body.(*journal.MsgRec)
				if !ok || fmt.Sprintf("%020d.wal", position.Segment) != row.File || message.Dir != journal.In || len(message.Payload) > 16<<20 {
					return nil, 0, failure
				}
				payload, code = append([]byte(nil), message.Payload...), message.Code
			}
		}
	case "frames":
		root, e := os.OpenRoot(p.Input.Path)
		if e != nil {
			return nil, 0, failure
		}
		defer root.Close()
		if !shaPattern.MatchString(row.PayloadSHA256) {
			return nil, 0, failure
		}
		file, e := root.Open("payloads/" + row.PayloadSHA256[:2] + "/" + row.PayloadSHA256)
		if e != nil {
			return nil, 0, failure
		}
		payload, e = io.ReadAll(io.LimitReader(file, (16<<20)+1))
		file.Close()
		if e != nil || len(payload) > 16<<20 {
			return nil, 0, failure
		}
		switch row.Phase {
		case "PRE-PREPARE":
			code = 0x12
		case "PREPARE":
			code = 0x13
		case "COMMIT":
			code = 0x14
		case "ROUND-CHANGE":
			code = 0x15
		default:
			return nil, 0, failure
		}
	default:
		return nil, 0, failure
	}
	hash := sha256.Sum256(payload)
	after, err := Fingerprint(ctx, p.Input)
	if err != nil || after.SHA256 != before.SHA256 || hex.EncodeToString(hash[:]) != row.PayloadSHA256 || phase(code) != row.Phase {
		return nil, 0, failure
	}
	return payload, code, nil
}
