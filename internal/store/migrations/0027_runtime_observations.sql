ALTER TABLE datasets DROP CONSTRAINT datasets_kind_check;
ALTER TABLE datasets ADD CONSTRAINT datasets_kind_check CHECK(kind IN ('run','range','follow','reports','messages','observations','runtime'));
CREATE TABLE runtime_observation_captures (
 dataset_id bigint PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
 capture jsonb NOT NULL
);
