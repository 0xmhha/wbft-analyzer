-- Full-number lookup never treats a low64 canonical index as RPC identity.
CREATE INDEX heights_full_number ON heights(network_id,(fact->>'number'));
CREATE TABLE observation_header_indexes (
 dataset_id bigint PRIMARY KEY REFERENCES observation_captures(dataset_id) ON DELETE CASCADE,
 version text NOT NULL,
 source_snapshot text NOT NULL,
 header_numbers jsonb NOT NULL,
 header_snapshot text NOT NULL,
 info jsonb NOT NULL
);
CREATE TABLE observation_header_rows (
 dataset_id bigint NOT NULL REFERENCES observation_header_indexes(dataset_id) ON DELETE CASCADE,
 ordinal bigint NOT NULL,
 height numeric(156,0),
 kind text NOT NULL,
 status text NOT NULL,
 row_ jsonb NOT NULL,
 PRIMARY KEY(dataset_id,ordinal)
);
CREATE INDEX observation_header_filter ON observation_header_rows(dataset_id,height,kind,status);
