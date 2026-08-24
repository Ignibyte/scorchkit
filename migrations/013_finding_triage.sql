-- Canonical append-only finding triage, correlation decisions, and scoped suppressions.

ALTER TABLE tracked_findings
    ADD COLUMN triage_state TEXT;

UPDATE tracked_findings
SET triage_state = CASE status
    WHEN 'new' THEN 'needs_context'
    WHEN 'acknowledged' THEN 'validated'
    WHEN 'false_positive' THEN 'false_positive'
    WHEN 'wont_fix' THEN 'accepted_risk'
    WHEN 'accepted_risk' THEN 'accepted_risk'
    WHEN 'remediated' THEN 'fixed'
    WHEN 'verified' THEN 'fixed'
    ELSE 'needs_context'
END;

ALTER TABLE tracked_findings
    ALTER COLUMN triage_state SET NOT NULL,
    ALTER COLUMN triage_state SET DEFAULT 'needs_context',
    ADD CONSTRAINT tracked_findings_triage_state_v1 CHECK (
        triage_state IN (
            'needs_context', 'likely', 'validated', 'false_positive',
            'accepted_risk', 'fixed', 'regressed'
        )
    );

CREATE TABLE finding_triage_transitions (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tracked_finding_id       UUID NOT NULL REFERENCES tracked_findings(id) ON DELETE CASCADE,
    transition_identity      TEXT NOT NULL,
    transition_schema        TEXT NOT NULL,
    sequence                 INTEGER NOT NULL CHECK (sequence > 0),
    from_state               TEXT,
    to_state                 TEXT NOT NULL,
    actor_kind               TEXT NOT NULL,
    actor_identity           TEXT NOT NULL,
    raw_transition           JSONB NOT NULL,
    observed_at              TIMESTAMPTZ NOT NULL,
    stored_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tracked_finding_id, transition_identity),
    UNIQUE(tracked_finding_id, sequence)
);

CREATE INDEX idx_finding_triage_transitions_parent
    ON finding_triage_transitions(tracked_finding_id, sequence);

WITH initial AS (
    SELECT id,
           stable_identity,
           triage_state,
           first_seen,
           'system'::text AS actor_kind,
           'migration/v1'::text AS actor_identity,
           'Migrated legacy finding status'::text AS reason,
           (
               extract(epoch FROM first_seen) * 1000000
           )::bigint::text AS observed_micros
    FROM tracked_findings
), identified AS (
    SELECT *, encode(digest(
        int8send(octet_length('scorchkit.finding-triage-transition/v1')::bigint)
            || convert_to('scorchkit.finding-triage-transition/v1', 'UTF8')
        || int8send(octet_length(stable_identity)::bigint) || convert_to(stable_identity, 'UTF8')
        || int8send(1::bigint) || convert_to('1', 'UTF8')
        || int8send(0::bigint)
        || int8send(octet_length(triage_state)::bigint) || convert_to(triage_state, 'UTF8')
        || int8send(octet_length(actor_kind)::bigint) || convert_to(actor_kind, 'UTF8')
        || int8send(octet_length(actor_identity)::bigint) || convert_to(actor_identity, 'UTF8')
        || int8send(octet_length(reason)::bigint) || convert_to(reason, 'UTF8')
        || int8send(0::bigint)
        || int8send(0::bigint)
        || int8send(octet_length(observed_micros)::bigint) || convert_to(observed_micros, 'UTF8'),
        'sha256'
    ), 'hex') AS transition_identity
    FROM initial
)
INSERT INTO finding_triage_transitions (
    tracked_finding_id, transition_identity, transition_schema, sequence, from_state, to_state,
    actor_kind, actor_identity, raw_transition, observed_at
)
SELECT id,
       transition_identity,
       'scorchkit.finding-triage-transition/v1',
       1,
       NULL,
       triage_state,
       actor_kind,
       actor_identity,
       jsonb_build_object(
           'schema', 'scorchkit.finding-triage-transition/v1',
           'identity', transition_identity,
           'finding_identity', stable_identity,
           'sequence', 1,
           'to', triage_state,
           'actor', jsonb_build_object('kind', actor_kind, 'identity', actor_identity),
           'reason', reason,
           'observed_at',
           to_char(first_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS') ||
           CASE
               WHEN extract(microseconds FROM first_seen)::bigint % 1000000 = 0 THEN 'Z'
               ELSE '.' || rtrim(
                   to_char(first_seen AT TIME ZONE 'UTC', 'US'), '0'
               ) || 'Z'
           END
       ),
       first_seen
FROM identified;

CREATE TABLE finding_correlation_decisions (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tracked_finding_id       UUID NOT NULL REFERENCES tracked_findings(id) ON DELETE CASCADE,
    decision_identity        TEXT NOT NULL,
    decision_schema          TEXT NOT NULL,
    actor_kind               TEXT NOT NULL,
    actor_identity           TEXT NOT NULL,
    raw_decision             JSONB NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL,
    stored_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tracked_finding_id, decision_identity)
);

CREATE INDEX idx_finding_correlation_decisions_parent
    ON finding_correlation_decisions(tracked_finding_id, created_at, decision_identity);

CREATE TABLE finding_suppressions (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id               UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    origin_finding_id        UUID NOT NULL REFERENCES tracked_findings(id) ON DELETE CASCADE,
    suppression_identity     TEXT NOT NULL,
    suppression_schema       TEXT NOT NULL,
    scope_kind               TEXT NOT NULL,
    finding_identity         TEXT,
    rule_identity            TEXT,
    target_identity          TEXT,
    actor_kind               TEXT NOT NULL,
    actor_identity           TEXT NOT NULL,
    raw_suppression          JSONB NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL,
    expires_at               TIMESTAMPTZ,
    review_at                TIMESTAMPTZ,
    stored_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, suppression_identity)
);

CREATE INDEX idx_finding_suppressions_project_time
    ON finding_suppressions(project_id, created_at, suppression_identity);

CREATE INDEX idx_finding_suppressions_exact_scope
    ON finding_suppressions(
        project_id, scope_kind, finding_identity, rule_identity, target_identity
    );

-- The mutable legacy column remains an adapter projection, not lifecycle authority.
UPDATE tracked_findings
SET status = CASE triage_state
    WHEN 'needs_context' THEN 'new'
    WHEN 'likely' THEN 'acknowledged'
    WHEN 'validated' THEN 'acknowledged'
    WHEN 'false_positive' THEN 'false_positive'
    WHEN 'accepted_risk' THEN 'accepted_risk'
    WHEN 'fixed' THEN 'verified'
    WHEN 'regressed' THEN 'new'
END;
