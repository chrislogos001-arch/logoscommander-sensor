-- Three anonymous counters. No other table, no request data.
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO counters (name, n) VALUES ('total', 0), ('blocks', 0), ('failures', 0);
