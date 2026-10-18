package store

import (
	"context"

	"github.com/0xmhha/wbft-analyzer/internal/reconstruct"
)

func (s *Store) ReconstructionReview(ctx context.Context, dataset, id, position int64) (reconstruct.ReviewPacket, error) {
	if position < 1 {
		return reconstruct.ReviewPacket{}, ErrNotFound
	}
	run, err := s.ReconstructionRun(ctx, dataset, id)
	if err != nil {
		return reconstruct.ReviewPacket{}, err
	}
	rows, err := s.ReconstructionSteps(ctx, id, position-1, "", "", false, 1)
	if err != nil {
		return reconstruct.ReviewPacket{}, err
	}
	if len(rows) != 1 || rows[0].Position != position {
		return reconstruct.ReviewPacket{}, ErrNotFound
	}
	row := rows[0]
	return reconstruct.ReviewStep(run.Summary, run.SHA256, row.Position, row.Height, row.Run, row.Step)
}
