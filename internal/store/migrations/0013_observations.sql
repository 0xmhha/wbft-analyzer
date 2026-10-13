-- Immutable read-only RPC claims; never native event completeness evidence.
ALTER TABLE datasets DROP CONSTRAINT datasets_kind_check;
ALTER TABLE datasets ADD CONSTRAINT datasets_kind_check CHECK(kind IN ('run','range','follow','reports','messages','observations'));
CREATE TABLE observation_captures (
 dataset_id bigint PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
 node text NOT NULL,
 snapshot text NOT NULL,
 info jsonb NOT NULL
);
CREATE TABLE observation_calls (
 dataset_id bigint NOT NULL REFERENCES observation_captures(dataset_id) ON DELETE CASCADE,
 ordinal bigint NOT NULL CHECK(ordinal>0),
 method text NOT NULL,
 call jsonb NOT NULL,
 PRIMARY KEY(dataset_id,ordinal)
);
CREATE TABLE observation_participation (
 dataset_id bigint NOT NULL REFERENCES observation_captures(dataset_id) ON DELETE CASCADE,
 height numeric(156,0) NOT NULL,
 ordinal bigint NOT NULL,
 row_ jsonb NOT NULL,
 PRIMARY KEY(dataset_id,height)
);
