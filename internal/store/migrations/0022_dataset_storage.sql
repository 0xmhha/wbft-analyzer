-- Each dataset owns a private input namespace, distinct from shared legacy CAS.
CREATE TABLE dataset_storage (
 dataset_id bigint PRIMARY KEY REFERENCES datasets(id) ON DELETE RESTRICT,
 root text NOT NULL,
 token text NOT NULL UNIQUE CHECK(token ~ '^[0-9a-f]{32}$'),
 owner text NOT NULL CHECK(owner ~ '^[0-9a-f]{64}$')
);
-- This journal survives deletion of the original dataset for cleanup retries.
CREATE TABLE dataset_deletions (
 dataset_id bigint PRIMARY KEY,
 network_id bigint NOT NULL,
 name text NOT NULL,
 status text NOT NULL CHECK(status IN ('deleting','deleted')),
 root text NOT NULL DEFAULT '',
 token text NOT NULL DEFAULT '',
 owner text NOT NULL DEFAULT '',
 files bigint NOT NULL CHECK(files>=0),
 bytes bigint NOT NULL CHECK(bytes>=0),
 created_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz
);
ALTER TABLE datasets DROP CONSTRAINT datasets_status_check;
ALTER TABLE datasets ADD CONSTRAINT datasets_status_check
 CHECK(status IN ('ready','importing','complete','failed','deleting'));
-- Interrupted adoption retains the candidate namespace for a verified retry.
CREATE TABLE dataset_storage_adoptions (
 dataset_id bigint PRIMARY KEY REFERENCES datasets(id) ON DELETE RESTRICT,
 root text NOT NULL,
 token text NOT NULL CHECK(token ~ '^[0-9a-f]{32}$'),
 owner text NOT NULL CHECK(owner ~ '^[0-9a-f]{64}$')
);
