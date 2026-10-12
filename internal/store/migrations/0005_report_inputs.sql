-- Only source identity is retained; input paths and raw payload are excluded.
CREATE TABLE report_inputs (
 report_id text NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
 input_id text NOT NULL,
 kind text NOT NULL,
 node text NOT NULL,
 sha256 text NOT NULL CHECK (sha256='' OR sha256 ~ '^[0-9a-f]{64}$'),
 profile text NOT NULL,
 PRIMARY KEY(report_id,input_id)
);
