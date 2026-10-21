CREATE TABLE IF NOT EXISTS map_settings (
 singleton TEXT PRIMARY KEY,
 provider TEXT NOT NULL DEFAULT 'carto',
 api_key TEXT NOT NULL DEFAULT ''
);
INSERT INTO map_settings(singleton) VALUES ('global') ON CONFLICT DO NOTHING;
