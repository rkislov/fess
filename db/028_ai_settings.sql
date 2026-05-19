-- Настройки ИИ (переопределяют FENCE_AI_* из окружения policy-api, если поля в БД не пустые).
CREATE TABLE IF NOT EXISTS ai_settings (
  singleton TEXT PRIMARY KEY DEFAULT 'global' CHECK (singleton = 'global'),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  base_url TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  api_key TEXT NOT NULL DEFAULT '',
  http_timeout_sec INT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO ai_settings (singleton) VALUES ('global')
ON CONFLICT (singleton) DO NOTHING;
