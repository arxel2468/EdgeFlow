CREATE TABLE IF NOT EXISTS runs (
id TEXT PRIMARY KEY,
flow_id TEXT NOT NULL,
status TEXT NOT NULL, -- 'queued' | 'running' | 'succeeded' | 'failed'
started_at INTEGER,
finished_at INTEGER,
error TEXT,
input TEXT -- JSON string of trigger payload (optional)
);
CREATE INDEX IF NOT EXISTS idx_runs_flow ON runs(flow_id);

CREATE TABLE IF NOT EXISTS run_logs (
id TEXT PRIMARY KEY,
run_id TEXT NOT NULL,
ts INTEGER NOT NULL,
level TEXT NOT NULL, -- 'info' | 'warn' | 'error'
message TEXT NOT NULL,
data TEXT -- JSON string
);
CREATE INDEX IF NOT EXISTS idx_run_logs_run ON run_logs(run_id);

