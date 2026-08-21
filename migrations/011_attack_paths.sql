-- Versioned source-to-runtime attack paths and append-preserved state transitions.

CREATE TABLE attack_paths (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    path_identity       TEXT NOT NULL,
    path_schema         TEXT NOT NULL,
    identity_schema     TEXT NOT NULL,
    current_state       TEXT NOT NULL,
    raw_path            JSONB NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, path_identity)
);

CREATE INDEX idx_attack_paths_project_state
    ON attack_paths(project_id, current_state, path_identity);

CREATE TABLE attack_path_transitions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_path_id      UUID NOT NULL REFERENCES attack_paths(id) ON DELETE CASCADE,
    transition_identity TEXT NOT NULL,
    transition_schema   TEXT NOT NULL,
    raw_transition      JSONB NOT NULL,
    observed_at         TIMESTAMPTZ NOT NULL,
    stored_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(attack_path_id, transition_identity)
);

CREATE INDEX idx_attack_path_transitions_path_time
    ON attack_path_transitions(attack_path_id, observed_at, transition_identity);
