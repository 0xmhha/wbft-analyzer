-- The tables of stage A0: networks, datasets and inspector reports with
-- their results and observations (design.md 7).

CREATE TABLE networks (
    id           bigserial PRIMARY KEY,
    chain_id     text NOT NULL,
    genesis_hash text NOT NULL,
    name         text NOT NULL,
    visibility   text NOT NULL CHECK (visibility IN ('public', 'private')),
    UNIQUE (chain_id, genesis_hash)
);

CREATE TABLE datasets (
    id         bigserial PRIMARY KEY,
    network_id bigint REFERENCES networks (id) ON DELETE CASCADE,
    name       text NOT NULL UNIQUE,
    kind       text NOT NULL CHECK (kind IN ('run', 'range', 'follow', 'reports')),
    visibility text NOT NULL CHECK (visibility IN ('public', 'private')),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- A report is keyed by the sha256 of its file: loading the same file again
-- adds nothing.
CREATE TABLE reports (
    id                text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{64}$'),
    dataset_id        bigint REFERENCES datasets (id) ON DELETE CASCADE,
    run_id            text NOT NULL,
    started_at        text NOT NULL,
    finished_at       text NOT NULL,
    inspector_version text NOT NULL,
    inspector_commit  text NOT NULL,
    catalog_sha256    text NOT NULL,
    spec_commit       text NOT NULL,
    network           jsonb,
    range_            jsonb,
    summary           jsonb NOT NULL,
    loaded_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE results (
    report_id   text NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    requirement text NOT NULL,
    node        text NOT NULL DEFAULT '',
    verdict     text NOT NULL,
    coverage    jsonb,
    PRIMARY KEY (report_id, requirement, node)
);

CREATE TABLE observations (
    report_id    text NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    obs_id       text NOT NULL,
    kind         text NOT NULL,
    imp          text[] NOT NULL DEFAULT '{}',
    requirements text[] NOT NULL DEFAULT '{}',
    node         text NOT NULL DEFAULT '',
    count        bigint NOT NULL,
    first_at     text NOT NULL DEFAULT '',
    last_at      text NOT NULL DEFAULT '',
    PRIMARY KEY (report_id, obs_id)
);

CREATE INDEX observations_kind ON observations (kind);
