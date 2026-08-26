-- Hard cell identity, encrypted object metadata, and append-only team audit.

CREATE TABLE team_cell_identity (
    singleton       BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    cell_id         TEXT NOT NULL CHECK (char_length(cell_id) BETWEEN 1 AND 128),
    organization_id TEXT NOT NULL CHECK (char_length(organization_id) BETWEEN 1 AND 128),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    engagement_id   UUID NOT NULL,
    provisioned_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE team_objects (
    object_id         TEXT PRIMARY KEY CHECK (
        char_length(object_id) = 64 AND object_id = lower(object_id)
        AND object_id ~ '^[0-9a-f]{64}$'
    ),
    kind              TEXT NOT NULL CHECK (
        kind IN ('evidence', 'report', 'extension_artifact')
    ),
    plaintext_bytes   BIGINT NOT NULL CHECK (plaintext_bytes > 0),
    ciphertext_sha256 TEXT NOT NULL CHECK (
        char_length(ciphertext_sha256) = 64 AND ciphertext_sha256 = lower(ciphertext_sha256)
        AND ciphertext_sha256 ~ '^[0-9a-f]{64}$'
    ),
    stored_bytes      BIGINT NOT NULL CHECK (stored_bytes > 0),
    key_id            TEXT NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    created_at        TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at)
);

CREATE INDEX idx_team_objects_expiry ON team_objects(expires_at, object_id);

CREATE TABLE team_object_deletions (
    object_id         TEXT NOT NULL CHECK (
        char_length(object_id) = 64 AND object_id = lower(object_id)
        AND object_id ~ '^[0-9a-f]{64}$'
    ),
    ciphertext_sha256 TEXT NOT NULL CHECK (
        char_length(ciphertext_sha256) = 64 AND ciphertext_sha256 = lower(ciphertext_sha256)
        AND ciphertext_sha256 ~ '^[0-9a-f]{64}$'
    ),
    queued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (object_id, ciphertext_sha256)
);

CREATE TABLE team_request_ids (
    request_id    UUID PRIMARY KEY CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
    admitted_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE team_audit_events (
    sequence      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    request_id    UUID NOT NULL REFERENCES team_request_ids(request_id) ON DELETE RESTRICT,
    cell_id       TEXT NOT NULL CHECK (char_length(cell_id) BETWEEN 1 AND 128),
    organization_id TEXT NOT NULL CHECK (char_length(organization_id) BETWEEN 1 AND 128),
    project_id    UUID NOT NULL,
    engagement_id UUID NOT NULL,
    subject       TEXT NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 128),
    role          TEXT NOT NULL CHECK (role IN ('reader', 'analyst', 'operator', 'administrator')),
    action        TEXT NOT NULL CHECK (char_length(action) BETWEEN 1 AND 128),
    outcome       TEXT NOT NULL CHECK (
        outcome IN ('pending', 'succeeded', 'denied', 'failed', 'outcome_unknown')
    ),
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_team_audit_request ON team_audit_events(request_id, sequence);

CREATE FUNCTION reject_team_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'team audit history is append-only';
END;
$$;

CREATE TRIGGER team_audit_events_append_only
BEFORE UPDATE OR DELETE ON team_audit_events
FOR EACH ROW EXECUTE FUNCTION reject_team_audit_mutation();

CREATE TRIGGER team_request_ids_append_only
BEFORE UPDATE OR DELETE ON team_request_ids
FOR EACH ROW EXECUTE FUNCTION reject_team_audit_mutation();

CREATE TRIGGER team_cell_identity_immutable
BEFORE UPDATE OR DELETE ON team_cell_identity
FOR EACH ROW EXECUTE FUNCTION reject_team_audit_mutation();
