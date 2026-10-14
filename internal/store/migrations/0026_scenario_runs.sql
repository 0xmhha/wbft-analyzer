-- Network experiments retain seed executions separately from canonical facts.
CREATE TABLE scenario_runs (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 dataset_id bigint NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
 provenance jsonb NOT NULL CHECK(jsonb_typeof(provenance)='object'),
 source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 change jsonb NOT NULL CHECK(jsonb_typeof(change)='object'),
 change_sha256 text NOT NULL CHECK(change_sha256 ~ '^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN ('running','completed','partial','failed')),
 summary jsonb NOT NULL CHECK(jsonb_typeof(summary)='object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz
);
CREATE INDEX scenario_runs_dataset ON scenario_runs(dataset_id,id DESC);
CREATE TABLE scenario_seed_results (
 run_id bigint NOT NULL REFERENCES scenario_runs(id) ON DELETE CASCADE,
 mode text NOT NULL CHECK(mode IN ('baseline','counterfactual')),
 seed_index integer NOT NULL CHECK(seed_index BETWEEN 1 AND 128),
 seed bigint NOT NULL,
 status text NOT NULL CHECK(status IN ('complete','partial','violations')),
 record jsonb NOT NULL CHECK(jsonb_typeof(record)='object'),
 PRIMARY KEY(run_id,mode,seed_index),
 UNIQUE(run_id,mode,seed)
);
CREATE TABLE scenario_jobs (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 dataset_id bigint NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
 source_id text NOT NULL,
 source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 execution_sha256 text NOT NULL CHECK(execution_sha256 ~ '^[0-9a-f]{64}$'),
 change jsonb NOT NULL CHECK(jsonb_typeof(change)='object'),
 change_sha256 text NOT NULL CHECK(change_sha256 ~ '^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN ('queued','running','succeeded','failed','cancelled')),
 owner text NOT NULL DEFAULT '',
 scenario_id bigint REFERENCES scenario_runs(id) ON DELETE RESTRICT,
 issue text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(),
 started_at timestamptz,
 finished_at timestamptz
);
CREATE INDEX scenario_jobs_queue ON scenario_jobs(id) WHERE status='queued';
CREATE INDEX scenario_jobs_dataset ON scenario_jobs(dataset_id,id DESC);
CREATE TABLE scenario_sources (
 dataset_id bigint NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
 source_id text NOT NULL,
 declaration_sha256 text NOT NULL CHECK(declaration_sha256 ~ '^[0-9a-f]{64}$'),
 source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 execution_sha256 text NOT NULL CHECK(execution_sha256='' OR execution_sha256 ~ '^[0-9a-f]{64}$'),
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object'),
 PRIMARY KEY(dataset_id,source_id)
);
