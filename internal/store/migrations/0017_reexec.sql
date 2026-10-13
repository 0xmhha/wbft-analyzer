-- Closed replay observations remain separate from canonical network facts.
CREATE TABLE reexec_runs (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 dataset_id bigint NOT NULL,
 input_id text NOT NULL,
 from_height numeric(20,0) NOT NULL,
 to_height numeric(20,0) NOT NULL CHECK(to_height>=from_height),
 chain_path text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz,
 status text NOT NULL CHECK(status IN ('running','failed','not_possible','partial','regression','diverged','reproduced')),
 summary jsonb NOT NULL,
 FOREIGN KEY(dataset_id,input_id) REFERENCES message_inputs(dataset_id,input_id) ON DELETE RESTRICT
);
CREATE TABLE reexec_steps (
 run_id bigint NOT NULL REFERENCES reexec_runs(id) ON DELETE CASCADE,
 ordinal bigint NOT NULL CHECK(ordinal>0),
 height numeric(156,0) NOT NULL,
 class text NOT NULL CHECK(class IN ('match','output_diverged','env_mismatch','env_exhausted','input_gap','not_comparable')),
 record jsonb NOT NULL,
 PRIMARY KEY(run_id,ordinal)
);
CREATE INDEX reexec_runs_dataset ON reexec_runs(dataset_id,id DESC);
