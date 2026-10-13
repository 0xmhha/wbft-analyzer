-- A cursor advances only after its immutable header and native captures exist.
CREATE TABLE follow_cursors (
 dataset_id bigint PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
 next_index numeric(20,0) NOT NULL CHECK(next_index >= 0 AND next_index <= 18446744073709551615),
 parent_hash text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE follow_batches (
 dataset_id bigint NOT NULL REFERENCES follow_cursors(dataset_id) ON DELETE CASCADE,
 from_index numeric(20,0) NOT NULL,
 to_index numeric(20,0) NOT NULL CHECK(to_index >= from_index),
 headers_dataset bigint NOT NULL REFERENCES datasets(id) ON DELETE RESTRICT,
 observations_dataset bigint NOT NULL REFERENCES datasets(id) ON DELETE RESTRICT,
 PRIMARY KEY(dataset_id,from_index)
);
