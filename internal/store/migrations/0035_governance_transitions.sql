-- Transition evidence shares the complete replay's canonical dependency and
-- lifetime. Source deletion invalidates that dependency without reassignment.
CREATE TABLE governance_transition_witnesses (
 dataset_id bigint NOT NULL,
 snapshot text NOT NULL CHECK(snapshot ~ '^[0-9a-f]{64}$'),
 execution_snapshot text NOT NULL,
 info jsonb NOT NULL CHECK(jsonb_typeof(info)='object'),
 PRIMARY KEY(dataset_id,snapshot),
 FOREIGN KEY(dataset_id,execution_snapshot) REFERENCES governance_execution_witnesses(dataset_id,snapshot) ON DELETE CASCADE
);
CREATE TABLE governance_transition_blocks (
 dataset_id bigint NOT NULL,
 snapshot text NOT NULL,
 index_ numeric(20,0) NOT NULL CHECK(index_>=0 AND index_<=18446744073709551615),
 block jsonb NOT NULL CHECK(jsonb_typeof(block)='object'),
 PRIMARY KEY(dataset_id,snapshot,index_),
 FOREIGN KEY(dataset_id,snapshot) REFERENCES governance_transition_witnesses(dataset_id,snapshot) ON DELETE CASCADE
);
CREATE TABLE governance_transition_transactions (
 dataset_id bigint NOT NULL,
 snapshot text NOT NULL,
 index_ numeric(20,0) NOT NULL,
 tx_ordinal integer NOT NULL CHECK(tx_ordinal>=0),
 point jsonb NOT NULL CHECK(jsonb_typeof(point)='object'),
 PRIMARY KEY(dataset_id,snapshot,index_,tx_ordinal),
 FOREIGN KEY(dataset_id,snapshot,index_) REFERENCES governance_transition_blocks(dataset_id,snapshot,index_) ON DELETE CASCADE
);
CREATE INDEX governance_transition_transactions_lookup ON governance_transition_transactions(dataset_id,index_,tx_ordinal,snapshot);
