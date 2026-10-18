-- Source-bound log reconstruction is separate from native journal replay.
-- Only closed metadata projections are retained; no local paths or bytes.
CREATE TABLE reconstruction_runs (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 dataset_id bigint NOT NULL,
 input_id text NOT NULL,
 from_height numeric(156,0) NOT NULL,
 to_height numeric(156,0) NOT NULL CHECK(to_height>=from_height),
 result_sha256 text NOT NULL CHECK(result_sha256 ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 height_count bigint NOT NULL CHECK(height_count>0),
 complete_heights bigint NOT NULL CHECK(complete_heights>=0),
 step_count bigint NOT NULL CHECK(step_count>=0),
 differences bigint NOT NULL CHECK(differences>=0),
 summary jsonb NOT NULL,
 FOREIGN KEY(dataset_id,input_id) REFERENCES log_inputs(dataset_id,input_id) ON DELETE CASCADE,
 UNIQUE(dataset_id,input_id,result_sha256)
);
CREATE TABLE reconstruction_steps (
 run_id bigint NOT NULL REFERENCES reconstruction_runs(id) ON DELETE CASCADE,
 position bigint NOT NULL CHECK(position>0),
 height numeric(156,0) NOT NULL,
 log_run text NOT NULL,
 different boolean NOT NULL,
 record jsonb NOT NULL,
 PRIMARY KEY(run_id,position)
);
CREATE INDEX reconstruction_runs_dataset ON reconstruction_runs(dataset_id,id DESC);
CREATE INDEX reconstruction_steps_height ON reconstruction_steps(run_id,height,position);
