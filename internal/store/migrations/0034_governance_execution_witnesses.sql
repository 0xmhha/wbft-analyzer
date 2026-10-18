-- Execution evidence belongs to its capture; a removed canonical source must
-- invalidate the binding without erasing the historical implementation digest.
CREATE TABLE governance_execution_witnesses (
 dataset_id bigint NOT NULL REFERENCES governance_captures(dataset_id) ON DELETE CASCADE,
 snapshot text NOT NULL CHECK(snapshot ~ '^[0-9a-f]{64}$'),
 header_dataset_id bigint REFERENCES datasets(id) ON DELETE SET NULL,
 header_source_id bigint NOT NULL CHECK(header_source_id>0),
 info jsonb NOT NULL CHECK(jsonb_typeof(info)='object'),
 PRIMARY KEY(dataset_id,snapshot)
);
CREATE TABLE governance_execution_blocks (
 dataset_id bigint NOT NULL,
 snapshot text NOT NULL,
 index_ numeric(20,0) NOT NULL CHECK(index_>=0 AND index_<=18446744073709551615),
 block jsonb NOT NULL CHECK(jsonb_typeof(block)='object'),
 PRIMARY KEY(dataset_id,snapshot,index_),
 FOREIGN KEY(dataset_id,snapshot) REFERENCES governance_execution_witnesses(dataset_id,snapshot) ON DELETE CASCADE
);
CREATE TABLE governance_execution_transactions (
 dataset_id bigint NOT NULL,
 snapshot text NOT NULL,
 index_ numeric(20,0) NOT NULL,
 tx_ordinal integer NOT NULL CHECK(tx_ordinal>=0),
 point jsonb NOT NULL CHECK(jsonb_typeof(point)='object'),
 PRIMARY KEY(dataset_id,snapshot,index_,tx_ordinal),
 FOREIGN KEY(dataset_id,snapshot,index_) REFERENCES governance_execution_blocks(dataset_id,snapshot,index_) ON DELETE CASCADE
);
CREATE INDEX governance_execution_transactions_lookup ON governance_execution_transactions(dataset_id,index_,tx_ordinal,snapshot);
