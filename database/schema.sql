CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    filename TEXT,
    sender TEXT,
    subject TEXT,
    verdict TEXT NOT NULL,
    attack_type TEXT,
    risk_score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    ml_probability REAL,
    sender_risk INTEGER,
    url_risk INTEGER,
    content_risk INTEGER,
    attachment_risk INTEGER,
    impersonation_risk INTEGER,
    suspicious_indicators TEXT,
    ai_explanation TEXT,
    explanation_source TEXT,
    url_count INTEGER,
    attachment_count INTEGER,
    input_source TEXT
);

CREATE INDEX IF NOT EXISTS idx_analyses_timestamp ON analyses(timestamp);
CREATE INDEX IF NOT EXISTS idx_analyses_verdict ON analyses(verdict);
