-- Range bounds include every recorded candidate, before preview truncation.
-- Old projections require reindexing to populate precise nanosecond bounds.
ALTER TABLE message_pairs ADD COLUMN observed_from_ns numeric(22,0);
ALTER TABLE message_pairs ADD COLUMN observed_to_ns numeric(22,0);
CREATE INDEX message_pairs_overlap ON message_pairs(dataset_id,observed_to_ns,observed_from_ns);
