-- Missing projections preserve their explicit run, companion and header scope.
CREATE TABLE missing_indexes (
 dataset_id bigint PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
 version text NOT NULL,
 from_index numeric(20,0) NOT NULL,
 to_index numeric(20,0) NOT NULL,
 status text NOT NULL,
 progress bigint NOT NULL,
 metadata jsonb NOT NULL,
 input_snapshot text NOT NULL,
 message_id bigint REFERENCES datasets(id) ON DELETE SET NULL,
 had_messages boolean NOT NULL,
 message_snapshot text NOT NULL,
 header_numbers jsonb NOT NULL,
 header_snapshot text NOT NULL,
 info jsonb NOT NULL
);
CREATE TABLE missing_cells (
 dataset_id bigint NOT NULL REFERENCES missing_indexes(dataset_id) ON DELETE CASCADE,
 ordinal bigint NOT NULL,
 index_ numeric(20,0) NOT NULL,
 validator text NOT NULL,
 phase text NOT NULL,
 class text NOT NULL,
 reason text NOT NULL,
 cell jsonb NOT NULL,
 PRIMARY KEY(dataset_id,ordinal)
);
CREATE INDEX missing_cells_filter ON missing_cells(dataset_id,index_,validator,phase,class);
