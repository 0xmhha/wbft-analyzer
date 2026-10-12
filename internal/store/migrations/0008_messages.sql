ALTER TABLE datasets DROP CONSTRAINT datasets_kind_check;
ALTER TABLE datasets ADD CONSTRAINT datasets_kind_check CHECK(kind IN ('run','range','follow','reports','messages'));
-- Immutable message provenance; metadata only, no payload or input bytes.
CREATE TABLE message_inputs (
 dataset_id bigint NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
 input_id text NOT NULL,
 node text NOT NULL,
 summary jsonb NOT NULL,
 stats jsonb NOT NULL DEFAULT '{}',
 PRIMARY KEY(dataset_id,input_id)
);
CREATE TABLE message_records (
 dataset_id bigint NOT NULL,
 input_id text NOT NULL,
 file text NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal>0),
 node text NOT NULL,
 run text NOT NULL,
 seq numeric(20,0) NOT NULL,
 type text NOT NULL,
 height numeric(156,0),
 round numeric(156,0),
 record jsonb NOT NULL,
 PRIMARY KEY(dataset_id,input_id,file,ordinal),
 UNIQUE(dataset_id,input_id,run,seq),
 FOREIGN KEY(dataset_id,input_id) REFERENCES message_inputs(dataset_id,input_id) ON DELETE CASCADE
);
CREATE INDEX message_records_view ON message_records(dataset_id,height,round,node);
