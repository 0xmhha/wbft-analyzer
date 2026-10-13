-- Payloads remain in a local private content-addressed directory.
CREATE TABLE input_files (
 dataset_id bigint NOT NULL,
 input_id text NOT NULL,
 name text NOT NULL,
 sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 bytes bigint NOT NULL CHECK(bytes >= 0),
 path text NOT NULL,
 PRIMARY KEY(dataset_id,input_id,name),
 FOREIGN KEY(dataset_id,input_id) REFERENCES message_inputs(dataset_id,input_id) ON DELETE CASCADE
);
