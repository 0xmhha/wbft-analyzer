-- Sanitized governance claims retain each request's independent scope.
ALTER TABLE datasets DROP CONSTRAINT datasets_kind_check;
ALTER TABLE datasets ADD CONSTRAINT datasets_kind_check
 CHECK(kind IN ('run','range','follow','reports','messages','observations','runtime','governance'));

CREATE TABLE governance_captures (
 dataset_id bigint PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
 node text NOT NULL,
 snapshot text NOT NULL,
 info jsonb NOT NULL
);
CREATE TABLE governance_calls (
 dataset_id bigint NOT NULL REFERENCES governance_captures(dataset_id) ON DELETE CASCADE,
 ordinal bigint NOT NULL CHECK(ordinal>0),
 method text NOT NULL,
 call jsonb NOT NULL,
 PRIMARY KEY(dataset_id,ordinal)
);
CREATE TABLE gov_ops (
 dataset_id bigint NOT NULL,
 call_ordinal bigint NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal>0),
 source_path text NOT NULL,
 number numeric(20,0) NOT NULL CHECK(number>=0 AND number<=18446744073709551615),
 instance text NOT NULL,
 tx_index bigint NOT NULL CHECK(tx_index>=0 AND tx_index<=4294967295),
 row_ jsonb NOT NULL,
 PRIMARY KEY(dataset_id,call_ordinal,ordinal),
 UNIQUE(dataset_id,call_ordinal,source_path),
 FOREIGN KEY(dataset_id,call_ordinal) REFERENCES governance_calls(dataset_id,ordinal) ON DELETE CASCADE
);
CREATE TABLE gov_gaps (
 dataset_id bigint NOT NULL,
 call_ordinal bigint NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal>0),
 number numeric(20,0) NOT NULL CHECK(number>=0 AND number<=18446744073709551615),
 kind text NOT NULL,
 gap_from numeric(20,0),
 gap_to numeric(20,0),
 row_ jsonb NOT NULL,
 PRIMARY KEY(dataset_id,call_ordinal,ordinal),
 FOREIGN KEY(dataset_id,call_ordinal) REFERENCES governance_calls(dataset_id,ordinal) ON DELETE CASCADE,
 CHECK((gap_from IS NULL)=(gap_to IS NULL)),
 CHECK(gap_from IS NULL OR (kind='gap' AND gap_from>=0 AND gap_to>=gap_from AND gap_to<=number))
);
CREATE TABLE gov_states (
 dataset_id bigint NOT NULL,
 call_ordinal bigint NOT NULL,
 number numeric(20,0) NOT NULL CHECK(number>=0 AND number<=18446744073709551615),
 instance text NOT NULL,
 row_ jsonb NOT NULL,
 PRIMARY KEY(dataset_id,call_ordinal),
 FOREIGN KEY(dataset_id,call_ordinal) REFERENCES governance_calls(dataset_id,ordinal) ON DELETE CASCADE
);
CREATE TABLE gov_proposals (
 dataset_id bigint NOT NULL,
 call_ordinal bigint NOT NULL,
 instance text NOT NULL,
 proposal_id numeric(20,0) NOT NULL CHECK(proposal_id>=0 AND proposal_id<=18446744073709551615),
 row_ jsonb NOT NULL,
 PRIMARY KEY(dataset_id,call_ordinal),
 FOREIGN KEY(dataset_id,call_ordinal) REFERENCES governance_calls(dataset_id,ordinal) ON DELETE CASCADE
);
CREATE TABLE gov_validator_changes (
 dataset_id bigint NOT NULL,
 call_ordinal bigint NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal>0),
 number numeric(20,0) NOT NULL CHECK(number>=0 AND number<=18446744073709551615),
 row_ jsonb NOT NULL,
 PRIMARY KEY(dataset_id,call_ordinal,ordinal),
 FOREIGN KEY(dataset_id,call_ordinal) REFERENCES governance_calls(dataset_id,ordinal) ON DELETE CASCADE
);
CREATE INDEX gov_ops_lookup ON gov_ops(dataset_id,number,instance,call_ordinal,ordinal);
CREATE INDEX gov_gaps_lookup ON gov_gaps(dataset_id,number,call_ordinal,ordinal);
CREATE INDEX gov_proposals_lookup ON gov_proposals(dataset_id,instance,proposal_id);
