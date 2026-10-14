package whatif

import "io"

func readBoundedChain(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, (64<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<20 {
		return nil, ErrEvidence
	}
	return raw, nil
}
