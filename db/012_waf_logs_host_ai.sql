-- Host header для привязки срабатывания к виртуальному сайту; кэш анализа ИИ по строке журнала
ALTER TABLE waf_logs ADD COLUMN IF NOT EXISTS host TEXT NOT NULL DEFAULT '';
ALTER TABLE waf_logs ADD COLUMN IF NOT EXISTS ai_analysis TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS waf_logs_created_at_rule_idx ON waf_logs (created_at DESC, rule_id);
