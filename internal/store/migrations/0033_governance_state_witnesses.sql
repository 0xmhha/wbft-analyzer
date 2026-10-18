-- Verified source metadata belongs to a governance capture. A deleted header
-- source leaves the original evidence available, but no longer bound.
CREATE TABLE governance_state_witnesses (
 dataset_id bigint NOT NULL REFERENCES governance_captures(dataset_id) ON DELETE CASCADE,
 snapshot text NOT NULL CHECK(snapshot ~ '^[0-9a-f]{64}$'),
 header_dataset_id bigint REFERENCES datasets(id) ON DELETE SET NULL,
 header_source_id bigint NOT NULL CHECK(header_source_id>0),
 info jsonb NOT NULL CHECK(jsonb_typeof(info)='object'),
 PRIMARY KEY(dataset_id,snapshot)
);
CREATE TABLE governance_state_points (
 dataset_id bigint NOT NULL,
 snapshot text NOT NULL,
 index_ numeric(20,0) NOT NULL CHECK(index_>=0 AND index_<=18446744073709551615),
 point jsonb NOT NULL CHECK(jsonb_typeof(point)='object'),
 PRIMARY KEY(dataset_id,snapshot,index_),
 FOREIGN KEY(dataset_id,snapshot) REFERENCES governance_state_witnesses(dataset_id,snapshot) ON DELETE CASCADE
);
CREATE INDEX governance_state_points_lookup ON governance_state_points(dataset_id,index_,snapshot);
