CREATE TABLE IF NOT EXISTS flows (
id TEXT PRIMARY KEY,
user_id TEXT NOT NULL,
name TEXT NOT NULL,
trigger_type TEXT NOT NULL, -- 'webhook' | 'cron'
trigger_secret TEXT, -- for 'webhook'
cron TEXT, -- for 'cron'
created_at INTEGER NOT NULL,
updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_user ON flows(user_id);

CREATE TABLE IF NOT EXISTS steps (
id TEXT PRIMARY KEY,
flow_id TEXT NOT NULL,
step_index INTEGER NOT NULL,
type TEXT NOT NULL, -- 'slack' | 'http' (we’ll add later)
config TEXT NOT NULL, -- JSON string
created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_steps_flow ON steps(flow_id);