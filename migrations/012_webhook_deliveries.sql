-- Durable, policy-owned webhook delivery queue.
--
-- The JSONB document contains only a redacted event, destination identity,
-- authorization snapshot, and lifecycle metadata. Indexed columns duplicate
-- the bounded subset needed for claiming, recovery, and revision CAS.

CREATE TABLE webhook_deliveries (
    id                UUID PRIMARY KEY,
    destination_id    TEXT NOT NULL,
    event_kind        TEXT NOT NULL,
    state             TEXT NOT NULL CHECK (
        state IN ('queued', 'delivering', 'succeeded', 'exhausted')
    ),
    revision          BIGINT NOT NULL CHECK (revision >= 0),
    attempts          INTEGER NOT NULL CHECK (attempts >= 0),
    owner_id          UUID,
    lease_expires_at  TIMESTAMPTZ,
    next_attempt_at   TIMESTAMPTZ,
    document          JSONB NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL,
    finished_at       TIMESTAMPTZ
);

CREATE INDEX idx_webhook_deliveries_created
    ON webhook_deliveries(created_at, id);
CREATE INDEX idx_webhook_deliveries_due
    ON webhook_deliveries(next_attempt_at, created_at, id)
    WHERE state = 'queued';
CREATE INDEX idx_webhook_deliveries_recovery
    ON webhook_deliveries(lease_expires_at, created_at, id)
    WHERE state = 'delivering';
CREATE INDEX idx_webhook_deliveries_pending_destination
    ON webhook_deliveries(destination_id)
    WHERE state IN ('queued', 'delivering');

CREATE TABLE webhook_delivery_audit_events (
    id           BIGSERIAL PRIMARY KEY,
    delivery_id  UUID NOT NULL REFERENCES webhook_deliveries(id) ON DELETE CASCADE,
    revision     BIGINT NOT NULL CHECK (revision >= 0),
    state        TEXT NOT NULL CHECK (
        state IN ('queued', 'delivering', 'succeeded', 'exhausted')
    ),
    attempts     INTEGER NOT NULL CHECK (attempts >= 0),
    occurred_at  TIMESTAMPTZ NOT NULL,
    event        JSONB NOT NULL,
    UNIQUE (delivery_id, revision)
);

CREATE INDEX idx_webhook_delivery_audit_state
    ON webhook_delivery_audit_events(state, occurred_at);
