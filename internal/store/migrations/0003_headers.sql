-- A1: canonical facts are shared by all datasets, while mutable seal copies
-- retain their dataset and node. Numeric indices cover all uint64 values.
ALTER TABLE datasets ADD COLUMN status text NOT NULL DEFAULT 'ready'
 CHECK (status IN ('ready','importing','complete','failed'));
ALTER TABLE datasets ADD COLUMN metadata jsonb NOT NULL DEFAULT '{}';
ALTER TABLE datasets ADD COLUMN progress bigint NOT NULL DEFAULT 0;
ALTER TABLE datasets ADD COLUMN error text NOT NULL DEFAULT '';
ALTER TABLE datasets ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE heights (
 network_id bigint NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
 index_ numeric(20,0) NOT NULL CHECK (index_ >= 0 AND index_ <= 18446744073709551615),
 hash text NOT NULL,
 fact jsonb NOT NULL,
 PRIMARY KEY (network_id,index_),
 UNIQUE (network_id,hash)
);
CREATE TABLE seals (
 network_id bigint NOT NULL,
 index_ numeric(20,0) NOT NULL,
 validator_idx integer NOT NULL CHECK (validator_idx >= 0),
 prev_prepared boolean NOT NULL,
 prev_committed boolean NOT NULL,
 PRIMARY KEY (network_id,index_,validator_idx),
 FOREIGN KEY (network_id,index_) REFERENCES heights(network_id,index_) ON DELETE CASCADE
);
CREATE TABLE epochs (
 network_id bigint NOT NULL,
 index_ numeric(20,0) NOT NULL,
 info jsonb NOT NULL,
 check_ text NOT NULL,
 detail text NOT NULL,
 PRIMARY KEY (network_id,index_),
 FOREIGN KEY (network_id,index_) REFERENCES heights(network_id,index_) ON DELETE CASCADE
);
CREATE TABLE header_copies (
 dataset_id bigint NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
 node text NOT NULL,
 index_ numeric(20,0) NOT NULL,
 hash text NOT NULL,
 copy jsonb NOT NULL,
 PRIMARY KEY (dataset_id,node,hash),
 UNIQUE(dataset_id,node,index_)
);
ALTER TABLE observations ADD COLUMN evidence jsonb NOT NULL DEFAULT '[]';
