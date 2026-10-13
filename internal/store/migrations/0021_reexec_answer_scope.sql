-- Persist explicit application response policy alongside the retained input mode.
ALTER TABLE reexec_jobs ADD COLUMN answer_scope text NOT NULL DEFAULT 'step' CHECK(answer_scope IN ('step','context'));
