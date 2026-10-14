-- Counterfactual executions never reuse canonical source ordinal keys.
CREATE TABLE whatif_runs (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 dataset_id bigint NOT NULL,
 input_id text NOT NULL,
 chain_path text NOT NULL,
 chain_sha256 text NOT NULL CHECK(chain_sha256 ~ '^[0-9a-f]{64}$'),
 source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 helper_sha256 text NOT NULL CHECK(helper_sha256 ~ '^[0-9a-f]{64}$'),
 policy jsonb NOT NULL CHECK(jsonb_typeof(policy)='object'),
 policy_sha256 text NOT NULL CHECK(policy_sha256 ~ '^[0-9a-f]{64}$'),
 execution_model text NOT NULL,
 status text NOT NULL CHECK(status IN ('running','completed','partial','failed')),
 created_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz,
 summary jsonb NOT NULL,
 FOREIGN KEY(dataset_id,input_id) REFERENCES message_inputs(dataset_id,input_id) ON DELETE RESTRICT
);
CREATE INDEX whatif_runs_dataset ON whatif_runs(dataset_id,id DESC);
CREATE TABLE whatif_results (
 run_id bigint NOT NULL REFERENCES whatif_runs(id) ON DELETE CASCADE,
 execution_step bigint NOT NULL CHECK(execution_step>0),
 height numeric(156,0),
 round numeric(156,0),
 t_mono_ns bigint NOT NULL CHECK(t_mono_ns>=0),
 generated boolean NOT NULL,
 record jsonb NOT NULL,
 PRIMARY KEY(run_id,execution_step)
);
CREATE INDEX whatif_results_view ON whatif_results(run_id,height,round,execution_step);
CREATE TABLE whatif_jobs (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 dataset_id bigint NOT NULL,
 input_id text NOT NULL,
 source_id text NOT NULL,
 source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 input_sha256 text NOT NULL CHECK(input_sha256 ~ '^[0-9a-f]{64}$'),
 chain_sha256 text NOT NULL CHECK(chain_sha256 ~ '^[0-9a-f]{64}$'),
 helper_sha256 text NOT NULL CHECK(helper_sha256 ~ '^[0-9a-f]{64}$'),
 policy jsonb NOT NULL CHECK(jsonb_typeof(policy)='object'),
 policy_sha256 text NOT NULL CHECK(policy_sha256 ~ '^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN ('queued','running','succeeded','failed','cancelled')),
 owner text NOT NULL DEFAULT '',
 whatif_id bigint REFERENCES whatif_runs(id) ON DELETE RESTRICT,
 issue text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(),
 started_at timestamptz,
 finished_at timestamptz,
 FOREIGN KEY(dataset_id,input_id) REFERENCES message_inputs(dataset_id,input_id) ON DELETE RESTRICT
);
CREATE INDEX whatif_jobs_queue ON whatif_jobs(id) WHERE status='queued';
CREATE INDEX whatif_jobs_dataset ON whatif_jobs(dataset_id,id DESC);
