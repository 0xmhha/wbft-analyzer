-- Preserve source coordinates while paginating in verified execution order.
ALTER TABLE reexec_steps ADD COLUMN execution_ordinal bigint;
UPDATE reexec_steps SET execution_ordinal=ordinal;
ALTER TABLE reexec_steps ALTER COLUMN execution_ordinal SET NOT NULL;
ALTER TABLE reexec_steps ADD CHECK(execution_ordinal>0);
CREATE UNIQUE INDEX reexec_steps_execution ON reexec_steps(run_id,execution_ordinal);
ALTER TABLE reexec_jobs ADD COLUMN input_schedule jsonb;
ALTER TABLE reexec_jobs ADD CHECK(input_schedule IS NULL OR (jsonb_typeof(input_schedule)='object' AND answer_scope='context' AND warmup_heights=0 AND mode='closed'));
