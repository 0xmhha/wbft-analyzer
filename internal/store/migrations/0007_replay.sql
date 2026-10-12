-- The visual axis preserves the original nanosecond timestamp. PostgreSQL's
-- timestamptz remains the general window index at microsecond precision.
ALTER TABLE log_events ADD COLUMN axis_ns numeric(22,0);
UPDATE log_events SET axis_ns = extract(epoch FROM date_trunc('second',t_wall))*1000000000
 + COALESCE(nullif(rpad((regexp_match(event->>'t_wall','\.([0-9]+)(Z|[+-][0-9:]+)$'))[1],9,'0'),''),'0')::numeric;
ALTER TABLE log_events ALTER COLUMN axis_ns SET NOT NULL;
CREATE INDEX log_events_replay ON log_events(dataset_id,node,axis_ns,input_id,line);
CREATE TABLE replay_indexes (
 dataset_id bigint PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
 progress bigint NOT NULL,
 version text NOT NULL,
 records bigint NOT NULL,
 frames bigint NOT NULL
);
CREATE TABLE replay_keyframes (
 dataset_id bigint NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
 node text NOT NULL,
 axis_ns numeric(22,0) NOT NULL,
 input_id text NOT NULL,
 line bigint NOT NULL,
 frame jsonb NOT NULL,
 PRIMARY KEY(dataset_id,node,axis_ns,input_id,line)
);
