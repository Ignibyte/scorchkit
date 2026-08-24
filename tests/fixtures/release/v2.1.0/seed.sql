INSERT INTO projects (id, name, description, settings, created_at, updated_at)
VALUES (
    '11111111-1111-4111-8111-111111111111',
    'release-upgrade-fixture',
    'v2.1.0 identity fixture',
    '{
      "engagement": {
        "id": "engagement-v2-release-fixture",
        "revision": 3,
        "history": ["created", "narrowed", "approved"]
      }
    }'::jsonb,
    '2025-01-01T00:00:00Z',
    '2025-01-02T00:00:00Z'
);

INSERT INTO project_targets (id, project_id, url, label, created_at)
VALUES (
    '22222222-2222-4222-8222-222222222222',
    '11111111-1111-4111-8111-111111111111',
    'https://fixture.example.test/app',
    'release fixture',
    '2025-01-01T01:00:00Z'
);

INSERT INTO scan_records (
    id, project_id, target_url, profile, started_at, completed_at,
    modules_run, modules_skipped, summary, created_at
)
VALUES (
    '33333333-3333-4333-8333-333333333333',
    '11111111-1111-4111-8111-111111111111',
    'https://fixture.example.test/app',
    'standard',
    '2025-01-03T00:00:00Z',
    '2025-01-03T00:05:00Z',
    ARRAY['headers', 'tls'],
    ARRAY['authenticated'],
    '{
      "job": {
        "id": "job-v2-release-fixture",
        "root_id": "job-root-v2-release-fixture",
        "history": [
          {"revision": 0, "state": "queued"},
          {"revision": 1, "state": "running"},
          {"revision": 2, "state": "succeeded"}
        ]
      },
      "evidence": {
        "id": "evidence-v2-release-fixture",
        "schema": "scorchkit.evidence/legacy-v1",
        "history": ["observed", "reported"]
      }
    }'::jsonb,
    '2025-01-03T00:05:01Z'
);

INSERT INTO tracked_findings (
    id, scan_id, project_id, fingerprint, module_id, severity, title, description,
    affected_target, evidence, remediation, owasp_category, cwe_id, raw_finding,
    first_seen, last_seen, seen_count, status, found_at, confidence, status_note
)
VALUES (
    '44444444-4444-4444-8444-444444444444',
    '33333333-3333-4333-8333-333333333333',
    '11111111-1111-4111-8111-111111111111',
    'release-fixture-fingerprint',
    'headers',
    'medium',
    'Release fixture finding',
    'Synthetic local upgrade fixture',
    'https://fixture.example.test/app',
    'evidence-v2-release-fixture',
    'Add the expected local header',
    'A05:2021',
    693,
    '{
      "finding_id": "finding-v2-release-fixture",
      "evidence_id": "evidence-v2-release-fixture",
      "history": [
        {"state": "new", "at": "2025-01-03T00:05:00Z"},
        {"state": "acknowledged", "at": "2025-01-04T00:00:00Z"}
      ]
    }'::jsonb,
    '2025-01-03T00:05:00Z',
    '2025-01-04T00:00:00Z',
    2,
    'acknowledged',
    '2025-01-03T00:05:00Z',
    0.75,
    'reviewed in v2.1.0'
);

INSERT INTO scan_schedules (
    id, project_id, target_url, profile, cron_expression, enabled,
    last_run, next_run, created_at
)
VALUES (
    '55555555-5555-4555-8555-555555555555',
    '11111111-1111-4111-8111-111111111111',
    'https://fixture.example.test/app',
    'standard',
    '0 2 * * *',
    true,
    '2025-01-03T02:00:00Z',
    '2025-01-04T02:00:00Z',
    '2025-01-01T02:00:00Z'
);

