CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    service_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    configuration JSON,
    security_score INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    description TEXT,
    remediation_steps TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_results(id)
);

CREATE TABLE IF NOT EXISTS compliance_results (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    standard_type TEXT NOT NULL,
    compliance_status BOOLEAN,
    findings JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_results(id)
);

CREATE TABLE IF NOT EXISTS risk_trends (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    service_type TEXT NOT NULL,
    risk_score INTEGER,
    affected_resources INTEGER,
    trend_data JSON
);
