-- A2 log metadata is source-bound and payload-free. Full heights and rounds
-- stay decimal strings in JSON; numeric filters support up to 512 bits.
CREATE TABLE log_inputs (
 dataset_id bigint NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
 input_id text NOT NULL,
 node text NOT NULL,
 profile text NOT NULL,
 profile_sha256 text NOT NULL CHECK (profile_sha256 ~ '^[0-9a-f]{64}$'),
 sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
 bytes bigint NOT NULL CHECK (bytes >= 0),
 stats jsonb NOT NULL DEFAULT '{}',
 PRIMARY KEY(dataset_id,input_id)
);
CREATE TABLE log_events (
 dataset_id bigint NOT NULL,
 input_id text NOT NULL,
 line bigint NOT NULL CHECK (line > 0),
 node text NOT NULL,
 run text NOT NULL,
 t_wall timestamptz NOT NULL,
 kind text NOT NULL,
 height numeric(156,0),
 round numeric(156,0),
 event jsonb NOT NULL,
 PRIMARY KEY(dataset_id,input_id,line),
 FOREIGN KEY(dataset_id,input_id) REFERENCES log_inputs(dataset_id,input_id) ON DELETE CASCADE
);
CREATE INDEX log_events_window ON log_events(dataset_id,t_wall,input_id,line);
CREATE INDEX log_events_height ON log_events(dataset_id,height,round,node);
