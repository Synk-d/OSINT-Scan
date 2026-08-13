-- OSINT Dashboard — relational schema
-- Matches Section A of the original proposal spec. Idempotent: safe to run
-- against an existing database.

-- Core target logging register
CREATE TABLE IF NOT EXISTS targets (
    id SERIAL PRIMARY KEY,
    target_type VARCHAR(20) NOT NULL CHECK (target_type IN ('domain', 'user', 'ip', 'email')),
    target_value VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Relational domain intelligence metadata tracking
CREATE TABLE IF NOT EXISTS domain_intel (
    id SERIAL PRIMARY KEY,
    target_id INT REFERENCES targets(id) ON DELETE CASCADE,
    subdomain VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    isp VARCHAR(150),
    country VARCHAR(10),
    region_name VARCHAR(150),
    city VARCHAR(150),
    lat DOUBLE PRECISION,
    lon DOUBLE PRECISION,
    registrar VARCHAR(100),
    mx_records TEXT[],
    raw_whois JSONB,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Real-time IP Intelligence & Region tracking
CREATE TABLE IF NOT EXISTS ip_intel (
    id SERIAL PRIMARY KEY,
    target_id INT REFERENCES targets(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    country VARCHAR(100),
    country_code VARCHAR(10),
    region_code VARCHAR(50),
    region_name VARCHAR(150),
    city VARCHAR(150),
    zip VARCHAR(30),
    lat DOUBLE PRECISION,
    lon DOUBLE PRECISION,
    timezone VARCHAR(100),
    isp VARCHAR(150),
    org VARCHAR(150),
    as_number VARCHAR(150),
    reverse_dns VARCHAR(255),
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Cross-platform profile identifier metrics
CREATE TABLE IF NOT EXISTS user_intel (
    id SERIAL PRIMARY KEY,
    target_id INT REFERENCES targets(id) ON DELETE CASCADE,
    platform VARCHAR(50) NOT NULL,
    profile_url TEXT NOT NULL,
    associated_email VARCHAR(255),
    bio_keywords TEXT[],
    confidence INT CHECK (confidence BETWEEN 0 AND 100),
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Inter-entity link analysis configuration
CREATE TABLE IF NOT EXISTS entity_relationships (
    id SERIAL PRIMARY KEY,
    source_target_id INT REFERENCES targets(id) ON DELETE CASCADE,
    destination_target_id INT REFERENCES targets(id) ON DELETE CASCADE,
    source_label VARCHAR(255) NOT NULL,
    destination_label VARCHAR(255) NOT NULL,
    relationship_type VARCHAR(50) NOT NULL,
    confidence_score INT CHECK (confidence_score BETWEEN 1 AND 100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_domain_intel_target ON domain_intel(target_id);
CREATE INDEX IF NOT EXISTS idx_ip_intel_target ON ip_intel(target_id);
CREATE INDEX IF NOT EXISTS idx_user_intel_target ON user_intel(target_id);
CREATE INDEX IF NOT EXISTS idx_relationships_source ON entity_relationships(source_target_id);
CREATE INDEX IF NOT EXISTS idx_relationships_dest ON entity_relationships(destination_target_id);
