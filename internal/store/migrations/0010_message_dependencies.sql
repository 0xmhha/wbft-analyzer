CREATE TABLE message_pair_dependencies (
 dataset_id bigint PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
 source_id bigint REFERENCES datasets(id) ON DELETE SET NULL,
 progress bigint NOT NULL,
 status text NOT NULL,
 metadata jsonb NOT NULL
);
