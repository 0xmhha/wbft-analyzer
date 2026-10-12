-- Event streams retain their pinned schema identity separately from logs.
ALTER TABLE log_inputs ADD COLUMN kind text NOT NULL DEFAULT 'log' CHECK (kind IN ('log','events'));
