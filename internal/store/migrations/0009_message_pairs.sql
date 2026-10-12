-- Derived metadata is versioned and bound to one immutable source snapshot.
CREATE TABLE message_pair_indexes (
 dataset_id bigint PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
 version text NOT NULL,
 progress bigint NOT NULL,
 status text NOT NULL,
 metadata jsonb NOT NULL,
 info jsonb NOT NULL
);
CREATE TABLE message_pairs (
 dataset_id bigint NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
 id text NOT NULL,
 axis_ns numeric(22,0),
 sender text NOT NULL,
 receiver text NOT NULL,
 phase text NOT NULL,
 height numeric(156,0),
 round numeric(156,0),
 strength text NOT NULL,
 path text NOT NULL,
 clock text NOT NULL,
 status text NOT NULL,
 pair jsonb NOT NULL,
 PRIMARY KEY(dataset_id,id)
);
CREATE INDEX message_pairs_window ON message_pairs(dataset_id,axis_ns,id);
CREATE INDEX message_pairs_direction ON message_pairs(dataset_id,sender,receiver,phase,strength,clock);
CREATE TABLE message_pair_issues (
 dataset_id bigint NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
 ordinal bigint NOT NULL,
 issue jsonb NOT NULL,
 PRIMARY KEY(dataset_id,ordinal)
);
