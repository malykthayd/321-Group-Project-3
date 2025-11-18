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

CREATE TABLE IF NOT EXISTS digest_preferences (
  id INT AUTO_INCREMENT PRIMARY KEY,
  slack_user_id VARCHAR(32) NULL,
  slack_channel_id VARCHAR(32) NULL,
  preference_name VARCHAR(64) DEFAULT 'default',
  medical_flag TINYINT(1) NULL,
  ics_flag TINYINT(1) NULL,
  bio_keyword_flag TINYINT(1) NULL,
  kev_flag TINYINT(1) NULL,
  min_cvss FLOAT NULL,
  min_bio_score INT NULL,
  limit_count INT DEFAULT 10,
  enabled TINYINT(1) DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY unique_user_pref (slack_user_id, preference_name),
  UNIQUE KEY unique_channel_pref (slack_channel_id, preference_name)
);
