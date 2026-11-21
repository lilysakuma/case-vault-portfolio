
-- ============================================================
-- CASE VAULT - DATABASE SCHEMA
-- ============================================================
--
-- This SQLite database stores cybersecurity incident records,
-- users, evidence, investigation tasks, affected assets,
-- incident tags, and known vulnerabilities.
--
-- The schema uses:
-- - Primary keys to uniquely identify records
-- - Foreign keys to establish relationships between tables
-- - CHECK constraints to restrict allowed values
-- - UNIQUE constraints to prevent duplicate records
-- - Indexes to improve lookup performance
-- ============================================================


-- Enable foreign key enforcement in SQLite.
-- This ensures referenced records must exist.
PRAGMA foreign_keys = ON;


-- ============================================================
-- USERS
-- ============================================================
-- Stores people who report, investigate, or administer incidents.
--
-- Roles:
-- reporter = submits incidents
-- analyst  = investigates incidents
-- admin    = administrative user
--
-- Email addresses must be unique.
-- Note: Roles are stored here, but application authorization
-- is not currently enforced by this schema alone.
-- ============================================================

CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('reporter', 'analyst', 'admin'))
);


-- ============================================================
-- INCIDENTS
-- ============================================================
-- Main table containing cybersecurity incident reports.
--
-- Each incident:
-- - Has a title, type, status, and severity
-- - Must have a reporter
-- - May have an assigned analyst or other user
-- - Tracks creation and update timestamps
--
-- Severity ranges from 1 to 5.
--
-- Foreign key relationships:
-- reporter_id -> users.user_id (required)
-- assignee_id -> users.user_id (optional)
-- ============================================================

CREATE TABLE incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    incident_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('new', 'triaged', 'investigating', 'resolved', 'closed')),
    severity INTEGER NOT NULL CHECK(severity BETWEEN 1 AND 5),
    reporter_id INTEGER NOT NULL,
    assignee_id INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reporter_id) REFERENCES users(user_id),
    FOREIGN KEY (assignee_id) REFERENCES users(user_id)
);


-- ============================================================
-- ASSETS
-- ============================================================
-- Stores devices, accounts, and servers that may be involved
-- in cybersecurity incidents.
--
-- The UNIQUE constraint prevents storing two assets with
-- the same asset type and identifier.
--
-- Example:
-- server | web-server-01 | IT Team
-- ============================================================

CREATE TABLE assets (
    asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_type TEXT NOT NULL CHECK(asset_type IN ('device', 'account', 'server')),
    identifier TEXT NOT NULL,
    owner TEXT,
    UNIQUE(asset_type, identifier)
);


-- ============================================================
-- EVIDENCE
-- ============================================================
-- Stores evidence associated with cybersecurity incidents.
--
-- Supported evidence types:
-- URL, domain, hash, CVE, email header, and file.
--
-- Each evidence record belongs to one incident.
-- added_by identifies the user who submitted the evidence.
--
-- The UNIQUE constraint prevents adding the same evidence
-- type and value more than once to the same incident.
--
-- Example:
-- Incident 2 | cve | CVE-2023-34362
-- ============================================================

CREATE TABLE evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    evidence_type TEXT NOT NULL CHECK(evidence_type IN ('url', 'domain', 'hash', 'cve', 'email_header', 'file')),
    value TEXT NOT NULL,
    file_path TEXT,
    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
    added_by INTEGER,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
    FOREIGN KEY (added_by) REFERENCES users(user_id),
    UNIQUE(incident_id, evidence_type, value)
);


-- ============================================================
-- TASKS
-- ============================================================
-- Tracks investigation and incident response activities.
--
-- Task types follow common incident response stages:
-- triage      = assess and prioritize the incident
-- contain     = limit the potential damage
-- eradicate   = remove the identified threat
-- recover     = restore affected systems
-- postmortem  = review the incident after response
--
-- Task status:
-- todo  = not started
-- doing = in progress
-- done  = completed
--
-- Each task belongs to an incident and records its creator.
-- ============================================================

CREATE TABLE tasks (
    task_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    created_by INTEGER NOT NULL,
    task_type TEXT NOT NULL CHECK(task_type IN ('triage', 'contain', 'eradicate', 'recover', 'postmortem')),
    status TEXT NOT NULL CHECK(status IN ('todo', 'doing', 'done')),
    due_date TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
    FOREIGN KEY (created_by) REFERENCES users(user_id)
);


-- ============================================================
-- TAGS
-- ============================================================
-- Stores reusable labels for categorizing incidents.
--
-- Examples:
-- phishing, vulnerability, critical, credential theft
--
-- Each tag name must be unique.
-- ============================================================

CREATE TABLE tags (
    tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);


-- ============================================================
-- INCIDENT_TAG - MANY-TO-MANY RELATIONSHIP
-- ============================================================
-- Connects incidents with tags.
--
-- An incident can have multiple tags.
-- A tag can belong to multiple incidents.
--
-- The composite primary key prevents the same tag from
-- being assigned twice to the same incident.
-- ============================================================

CREATE TABLE incident_tag (
    incident_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, tag_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
    FOREIGN KEY (tag_id) REFERENCES tags(tag_id)
);


-- ============================================================
-- INCIDENT_ASSET - MANY-TO-MANY RELATIONSHIP
-- ============================================================
-- Connects incidents with affected assets.
--
-- An incident can involve multiple assets.
-- An asset can be associated with multiple incidents.
--
-- The composite primary key prevents duplicate relationships.
-- ============================================================

CREATE TABLE incident_asset (
    incident_id INTEGER NOT NULL,
    asset_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, asset_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);


-- ============================================================
-- VULNERABILITIES
-- ============================================================
-- Stores known vulnerability information identified by CVE.
--
-- CVE = Common Vulnerabilities and Exposures.
--
-- Example:
-- CVE-2023-34362
-- Vendor: Progress
-- Product: MOVEit Transfer
-- Vulnerability: SQL Injection
--
-- The application matches CVE evidence against this table
-- to display additional vulnerability information.
--
-- This is a local lookup, not an automatic external API feed.
-- ============================================================

CREATE TABLE vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    vendor TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added TEXT
);


-- ============================================================
-- DATABASE INDEXES
-- ============================================================
-- Indexes help SQLite locate matching records more efficiently.
--
-- Evidence value:
-- Supports evidence searches and related-incident matching.
--
-- Incident status:
-- Supports queries filtering incidents by status.
--
-- Incident severity:
-- Supports queries filtering incidents by severity.
--
-- Indexes can improve reads but require additional storage
-- and maintenance when records are inserted or updated.
-- ============================================================

CREATE INDEX idx_evidence_value ON evidence(value);
CREATE INDEX idx_incident_status ON incidents(status);
CREATE INDEX idx_incident_severity ON incidents(severity);
