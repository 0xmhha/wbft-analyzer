-- Durable bounded replay work, separate from original network facts.
CREATE TABLE reexec_jobs (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 dataset_id bigint NOT NULL,
 input_id text NOT NULL,
 source_id text NOT NULL,
 source_sha256 text NOT NULL CHECK(length(source_sha256)=64),
 from_height numeric(20,0) NOT NULL CHECK(from_height>0),
 to_height numeric(20,0) NOT NULL CHECK(to_height>=from_height AND to_height-from_height<10000),
 mode text NOT NULL CHECK(mode IN ('closed','counterfactual')),
 status text NOT NULL CHECK(status IN ('queued','running','succeeded','failed','cancelled')),
 owner text NOT NULL DEFAULT '',
 reexec_id bigint REFERENCES reexec_runs(id) ON DELETE RESTRICT,
 issue text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(),
 started_at timestamptz,
 finished_at timestamptz,
 FOREIGN KEY(dataset_id,input_id) REFERENCES message_inputs(dataset_id,input_id) ON DELETE RESTRICT
);
CREATE INDEX reexec_jobs_queue ON reexec_jobs(id) WHERE status='queued';
CREATE INDEX reexec_jobs_dataset ON reexec_jobs(dataset_id,id DESC);
