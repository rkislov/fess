-- Optional demo seed data for local testing.
-- Apply manually after bootstrap if needed.

INSERT INTO policies(id, name, mode, priority, enabled)
VALUES ('11111111-1111-1111-1111-111111111111', 'default-blocking', 'block', 10, TRUE)
ON CONFLICT (id) DO NOTHING;

INSERT INTO rules(id, policy_id, name, action, priority, condition_json, transform_json, enabled)
VALUES
  (
    '22222222-2222-2222-2222-222222222221',
    '11111111-1111-1111-1111-111111111111',
    'block-basic-sqli-signature',
    'block',
    10,
    '{"body_contains":"'' OR ''1''=''1"}'::jsonb,
    '{}'::jsonb,
    TRUE
  ),
  (
    '22222222-2222-2222-2222-222222222222',
    '11111111-1111-1111-1111-111111111111',
    'block-xss-script-tag',
    'block',
    20,
    '{"body_contains":"<script>"}'::jsonb,
    '{}'::jsonb,
    TRUE
  ),
  (
    '22222222-2222-2222-2222-222222222223',
    '11111111-1111-1111-1111-111111111111',
    'block-path-traversal',
    'block',
    30,
    '{"path_contains":"../"}'::jsonb,
    '{}'::jsonb,
    TRUE
  )
ON CONFLICT (id) DO NOTHING;
