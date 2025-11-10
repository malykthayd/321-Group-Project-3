CREATE TABLE IF NOT EXISTS vulns (
  cve_id VARCHAR(32) PRIMARY KEY,
  title TEXT,
  description TEXT,
  cvss_base FLOAT,
  cvss_vector VARCHAR(128),
  severity VARCHAR(16),
  published DATE,
  last_modified DATE,
  vendor VARCHAR(128),
  product VARCHAR(128),
  source_list JSON,
  euvd_notes TEXT,
  advisory_url TEXT,
  plain_summary TEXT,
  safe_action TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tags (
  cve_id VARCHAR(32) PRIMARY KEY,
  kev_flag TINYINT(1) DEFAULT 0,
  ics_flag TINYINT(1) DEFAULT 0,
  medical_flag TINYINT(1) DEFAULT 0,
  bio_keyword_flag TINYINT(1) DEFAULT 0,
  recent_flag TINYINT(1) DEFAULT 0,
  cvss_high_flag TINYINT(1) DEFAULT 0,
  bio_score INT DEFAULT 0,
  source_count INT DEFAULT 1,
  confidence_level VARCHAR(16) DEFAULT 'low',
  conflict_flag TINYINT(1) DEFAULT 0,
  category_labels JSON,
  notes TEXT,
  last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (cve_id) REFERENCES vulns(cve_id) ON DELETE CASCADE
);
