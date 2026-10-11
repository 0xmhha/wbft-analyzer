-- Observation trends and alerts (design.md 6.7): a report belongs to the
-- network of its run when the run names one; its observations give rate
-- points; alert rules of a network keep their state.

ALTER TABLE reports ADD COLUMN network_id bigint REFERENCES networks (id) ON DELETE SET NULL;

CREATE TABLE trend_points (
    report_id  text NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    network_id bigint REFERENCES networks (id) ON DELETE CASCADE,
    kind       text NOT NULL,
    node       text NOT NULL DEFAULT '',
    rate       double precision NOT NULL,
    at         text NOT NULL,
    PRIMARY KEY (report_id, kind, node)
);

CREATE INDEX trend_points_series ON trend_points (network_id, kind, node, at);

CREATE TABLE alert_rules (
    id         bigserial PRIMARY KEY,
    network_id bigint NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    kind       text NOT NULL,
    node       text NOT NULL DEFAULT '',
    window_    integer NOT NULL CHECK (window_ >= 1),
    baseline   integer NOT NULL DEFAULT 0 CHECK (baseline >= 0),
    mode       text NOT NULL CHECK (mode IN ('absolute', 'relative')),
    threshold  double precision NOT NULL CHECK (threshold >= 0),
    webhook    text NOT NULL DEFAULT ''
);

CREATE TABLE alerts (
    rule_id    bigint PRIMARY KEY REFERENCES alert_rules (id) ON DELETE CASCADE,
    state      text NOT NULL CHECK (state IN ('pending', 'firing', 'resolved')),
    recent     double precision NOT NULL DEFAULT 0,
    baseline   double precision NOT NULL DEFAULT 0,
    changed_at timestamptz NOT NULL DEFAULT now()
);
