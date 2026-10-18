package inputobs

import "strconv"

func decodeAnswer(r record, line int64, missing map[string]bool) (Answer, error) {
	out := Answer{Method: r.Method, Line: line, Wall: r.Wall, Mono: r.Mono, Outcome: r.Outcome, DurationNS: r.DurationNS,
		ArgumentSHA: r.ArgumentSHA, SubjectHash: r.SubjectHash, HeadProposer: r.HeadProposer, Bad: r.Bad,
		PayloadAvailable: r.PayloadAvailable, PayloadSHA: r.PayloadSHA}
	if r.ArgumentSHA != "" && !digest.MatchString(r.ArgumentSHA) {
		return Answer{}, ErrInput
	}
	if r.SubjectHash != "" && !hashValue.MatchString(r.SubjectHash) {
		return Answer{}, ErrInput
	}
	payload := true
	switch r.Method {
	case "head":
		if r.Outcome != "available" && r.Outcome != "unavailable" || r.ArgumentSHA != "" || r.SubjectHash != "" || r.Bad != nil || r.DurationNS != "" {
			return Answer{}, ErrInput
		}
		if r.Outcome == "available" {
			if !address.MatchString(r.HeadProposer) {
				return Answer{}, ErrInput
			}
		} else {
			if r.HeadProposer != "" {
				return Answer{}, ErrInput
			}
			missing["head_answer_unavailable"] = true
			payload = false
		}
	case "validators_at":
		if r.Outcome != "available" && r.Outcome != "unavailable" || !digest.MatchString(r.ArgumentSHA) || r.HeadProposer != "" || r.SubjectHash != "" || r.Bad != nil || r.DurationNS != "" {
			return Answer{}, ErrInput
		}
		if r.Outcome == "unavailable" {
			missing["validator_answer_unavailable"] = true
			payload = false
		}
	case "verify":
		duration, err := strconv.ParseInt(r.DurationNS, 10, 64)
		if err != nil || strconv.FormatInt(duration, 10) != r.DurationNS || r.Outcome != "accepted" && r.Outcome != "future" && r.Outcome != "rejected" || r.ArgumentSHA != "" || r.HeadProposer != "" || r.SubjectHash != "" || r.Bad != nil {
			return Answer{}, ErrInput
		}
	case "bad_block":
		if !hashValue.MatchString(r.SubjectHash) || r.Bad == nil || r.Outcome != "" || r.ArgumentSHA != "" || r.HeadProposer != "" || r.DurationNS != "" {
			return Answer{}, ErrInput
		}
		payload = false
	case "commit_header":
		if r.Outcome != "accepted" && r.Outcome != "rejected" || !digest.MatchString(r.ArgumentSHA) || r.HeadProposer != "" || r.SubjectHash != "" || r.Bad != nil || r.DurationNS != "" {
			return Answer{}, ErrInput
		}
		payload = r.Outcome == "accepted"
	default:
		return Answer{}, ErrInput
	}
	if payload {
		var local Input
		if err := decodeInput(record{Kind: "request", PayloadAvailable: r.PayloadAvailable, PayloadSHA: r.PayloadSHA, Payload: r.Payload}, &local, missing); err != nil {
			return Answer{}, err
		}
		out.Payload = local.Payload
	} else if r.Payload != "" || r.PayloadSHA != "" || r.PayloadAvailable != nil && *r.PayloadAvailable {
		return Answer{}, ErrInput
	}
	return out, nil
}
