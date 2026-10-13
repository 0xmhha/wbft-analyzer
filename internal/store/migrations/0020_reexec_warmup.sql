-- Approximate post-prefix differences remain distinct from exact mismatches.
ALTER TABLE reexec_steps DROP CONSTRAINT reexec_steps_class_check;
ALTER TABLE reexec_steps ADD CHECK(class IN ('match','output_diverged','env_mismatch','env_exhausted','input_gap','not_comparable','warmup_suspect'));
ALTER TABLE reexec_jobs ADD COLUMN warmup_heights integer NOT NULL DEFAULT 2 CHECK(warmup_heights>=0 AND warmup_heights<=10000);
