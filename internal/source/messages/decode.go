package messages

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/types"
)

func number(n uint64) string { return strconv.FormatUint(n, 10) }
func signed(n int64) *string { s := strconv.FormatInt(n, 10); return &s }
func phase(code uint64) string {
	switch codec.Code(code) {
	case codec.CodePreprepare:
		return "PRE-PREPARE"
	case codec.CodePrepare:
		return "PREPARE"
	case codec.CodeCommit:
		return "COMMIT"
	case codec.CodeRoundChange:
		return "ROUND-CHANGE"
	}
	return ""
}
func choice(s string, values ...string) string {
	for _, v := range values {
		if s == v {
			return s
		}
	}
	return ""
}
func addr(a types.Address) string {
	if a == (types.Address{}) {
		return ""
	}
	return strings.ToLower(a.Hex())
}
func hash(h types.Hash) string {
	if h == (types.Hash{}) {
		return ""
	}
	return strings.ToLower(h.Hex())
}

// decode preserves the legacy-only interpretation of naked frame inputs.
func decode(r *Record, code uint64, payload []byte, truncated bool) {
	decodeDomain(r, code, payload, truncated, nil)
}

func decodeDomain(r *Record, code uint64, payload []byte, truncated bool, domain *types.RoundChangeDomain) {
	r.Phase = phase(code)
	if truncated || len(payload) == 0 {
		r.Decode = "missing_payload"
		return
	}
	sum := sha256.Sum256(payload)
	r.PayloadSHA256 = hex.EncodeToString(sum[:])
	key := strings.ToLower(codec.DedupKey(payload).Hex())
	if r.Key != "" && r.Key != key {
		r.Decode = "key_mismatch"
		return
	}
	r.Key = key
	if len(payload) > 16<<20 {
		r.Decode = "oversized"
		return
	}
	m, e := codec.DecodeMessage(codec.Code(code), payload)
	if e != nil {
		r.Decode = "invalid_message"
		return
	}
	if len(m.View.Sequence.String()) > 156 || len(m.View.Round.String()) > 156 {
		r.Decode = "oversized_view"
		return
	}
	r.Decode = "decoded"
	r.Height = m.View.Sequence.String()
	r.Round = m.View.Round.String()
	r.Digest = hash(m.Digest)
	if m.Proposal != nil {
		r.Digest = hash(codec.BlockHash(m.Proposal.Header))
	}
	r.Signature = "invalid"
	p, e := codec.SigningPayloadWithDomain(m, domain)
	if e != nil {
		return
	}
	a, e := ecdsa.RecoverDataSigner(p, m.Signature)
	if e == nil {
		r.Signature = "recovered"
		r.Signer = addr(a)
	}
}
func observe(s *Stats, r Record) {
	s.Records++
	if r.Type == "frame" {
		s.Frames++
		if r.Decode == "decoded" {
			s.Decoded++
		} else {
			s.Undecoded++
		}
		if r.Peer == "" {
			s.UnknownPeers++
		}
	}
	if r.Type == "gap" {
		s.GapRecords++
	}
}
