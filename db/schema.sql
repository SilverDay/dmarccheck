-- DMARC Report Analyzer — schema
-- MariaDB 10.11+ / utf8mb4. Implements spec §3, §10.5, §11.3, §15.8.

SET NAMES utf8mb4;

-- ---------------------------------------------------------------------------
-- Domains (§3.1)
-- ---------------------------------------------------------------------------
CREATE TABLE domains (
    id                       INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain                   VARCHAR(255) NOT NULL,
    -- Auto-read from DNS; never hand-entered (§10.6)
    current_published_policy VARCHAR(128) DEFAULT NULL,
    -- Admin-approved known-good baseline; R9 drift comparison target
    approved_baseline_policy VARCHAR(128) DEFAULT NULL,
    baseline_approved_at     DATETIME     DEFAULT NULL,
    baseline_approved_by     INT UNSIGNED DEFAULT NULL,
    -- Desired end state R7/R8 advance toward
    target_policy            VARCHAR(128) NOT NULL DEFAULT 'p=reject; sp=reject',
    non_sending              TINYINT(1)   NOT NULL DEFAULT 0,
    active                   TINYINT(1)   NOT NULL DEFAULT 1,
    created_at               DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_domain (domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Reports (§3.2)
-- ---------------------------------------------------------------------------
CREATE TABLE reports (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id     INT UNSIGNED NOT NULL,
    reporter_org  VARCHAR(255) NOT NULL,
    report_id     VARCHAR(255) NOT NULL,
    date_begin    DATETIME     NOT NULL,
    date_end      DATETIME     NOT NULL,
    -- SHA-256 of decompressed XML — idempotent re-ingestion
    raw_file_hash CHAR(64)     NOT NULL,
    received_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_report (domain_id, reporter_org, report_id),
    UNIQUE KEY uq_hash (raw_file_hash),
    KEY idx_domain_range (domain_id, date_begin),
    CONSTRAINT fk_reports_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Report records (§3.3)
-- ---------------------------------------------------------------------------
CREATE TABLE report_records (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    report_id   INT UNSIGNED    NOT NULL,
    -- Binary form via INET6_ATON — handles v4 and v6 uniformly
    source_ip   VARBINARY(16)   NOT NULL,
    `count`     INT UNSIGNED    NOT NULL,
    disposition ENUM('none','quarantine','reject') NOT NULL,
    dkim_result ENUM('pass','fail')                NOT NULL,
    spf_result  ENUM('pass','fail')                NOT NULL,
    header_from VARCHAR(255)    DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_report (report_id),
    KEY idx_source (source_ip),
    CONSTRAINT fk_records_report FOREIGN KEY (report_id) REFERENCES reports (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Auth results (§3.4)
-- ---------------------------------------------------------------------------
CREATE TABLE auth_results (
    id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    record_id BIGINT UNSIGNED NOT NULL,
    type      ENUM('dkim','spf') NOT NULL,
    domain    VARCHAR(255) DEFAULT NULL,
    selector  VARCHAR(255) DEFAULT NULL,
    result    VARCHAR(32)  DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_record (record_id),
    CONSTRAINT fk_auth_record FOREIGN KEY (record_id) REFERENCES report_records (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- IP enrichment (§3.5)
-- ---------------------------------------------------------------------------
CREATE TABLE ip_enrichment (
    source_ip VARBINARY(16) NOT NULL,
    rdns      VARCHAR(255)  DEFAULT NULL,
    asn       INT UNSIGNED  DEFAULT NULL,
    asn_org   VARCHAR(255)  DEFAULT NULL,
    label     VARCHAR(64)   NOT NULL DEFAULT 'unknown',
    last_seen DATETIME      DEFAULT NULL,
    lookup_at DATETIME      DEFAULT NULL,
    PRIMARY KEY (source_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Known senders allowlist (§3.6)
-- ---------------------------------------------------------------------------
CREATE TABLE known_senders (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id  INT UNSIGNED DEFAULT NULL,  -- NULL = applies to all domains
    ip_or_cidr VARCHAR(64)  NOT NULL,
    label      VARCHAR(128) NOT NULL,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_domain (domain_id),
    CONSTRAINT fk_known_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Recommendations (§10.5)
-- ---------------------------------------------------------------------------
CREATE TABLE recommendations (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id     INT UNSIGNED    NOT NULL,
    rule_id       VARCHAR(16)     NOT NULL,   -- R1..R12
    severity      ENUM('info','low','medium','high') NOT NULL,
    evidence_json JSON            DEFAULT NULL,
    first_seen    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    state         ENUM('open','acknowledged','suppressed','resolved') NOT NULL DEFAULT 'open',
    resolved_at   DATETIME        DEFAULT NULL,
    PRIMARY KEY (id),
    -- NB: no unique key on (domain_id, rule_id) — a rule can legitimately
    -- resolve and re-fire over time, so history must be allowed. The
    -- "only one OPEN row per rule" invariant is enforced in application
    -- logic (MariaDB has no partial/filtered unique indexes).
    KEY idx_domain_rule (domain_id, rule_id, state),
    KEY idx_domain_state (domain_id, state, severity),
    CONSTRAINT fk_rec_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Health checks (§11.3)
-- ---------------------------------------------------------------------------
CREATE TABLE health_checks (
    id        INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id INT UNSIGNED NOT NULL,
    run_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    trigger_  ENUM('onboarding','manual','scheduled') NOT NULL,
    PRIMARY KEY (id),
    KEY idx_domain_run (domain_id, run_at),
    CONSTRAINT fk_hc_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE health_check_items (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    check_id    INT UNSIGNED    NOT NULL,
    category    VARCHAR(64)     NOT NULL,   -- dns | transport | reputation
    check_name  VARCHAR(128)    NOT NULL,
    -- 'error' is distinct from 'fail': an un-run check is NOT a passing check (§11.3)
    status      ENUM('pass','warn','fail','info','error') NOT NULL,
    detail_json JSON            DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_check (check_id),
    CONSTRAINT fk_hci_check FOREIGN KEY (check_id) REFERENCES health_checks (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Users & auth (§15.8)
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    email           VARCHAR(255) NOT NULL,
    -- NULL for passkey-only users (§15.3)
    credential_hash VARCHAR(255) DEFAULT NULL,
    totp_secret     VARBINARY(255) DEFAULT NULL,  -- encrypted at rest
    role            ENUM('super_admin','admin','read_only') NOT NULL,
    status          ENUM('invited','active','disabled') NOT NULL DEFAULT 'invited',
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at   DATETIME     DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE webauthn_credentials (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id       INT UNSIGNED    NOT NULL,
    credential_id VARBINARY(255)  NOT NULL,
    public_key    BLOB            NOT NULL,
    sign_count    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    label         VARCHAR(128)    DEFAULT NULL,
    -- Remaining columns round-trip webauthn-lib's CredentialRecord (5.x) so a
    -- stored credential can be reconstructed exactly for the assertion ceremony.
    attestation_type VARCHAR(32)  DEFAULT NULL,
    aaguid           CHAR(36)     DEFAULT NULL,
    trust_path       JSON         DEFAULT NULL,
    transports       JSON         DEFAULT NULL,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at  DATETIME        DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_credential (credential_id),
    KEY idx_user (user_id),
    CONSTRAINT fk_wac_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE recovery_codes (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED    NOT NULL,
    code_hash   VARCHAR(255)    NOT NULL,
    consumed_at DATETIME        DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_user (user_id),
    CONSTRAINT fk_rc_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE invitations (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    email       VARCHAR(255) NOT NULL,
    token_hash  CHAR(64)     NOT NULL,   -- store hash, never the raw token
    role        ENUM('super_admin','admin','read_only') NOT NULL,
    invited_by  INT UNSIGNED DEFAULT NULL,
    expires_at  DATETIME     NOT NULL,
    consumed_at DATETIME     DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_token (token_hash),
    KEY idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE password_resets (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED NOT NULL,
    token_hash  CHAR(64)     NOT NULL,
    expires_at  DATETIME     NOT NULL,
    consumed_at DATETIME     DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_token (token_hash),
    KEY idx_user (user_id),
    CONSTRAINT fk_pr_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE sessions (
    id            CHAR(64)     NOT NULL,   -- session id hash
    user_id       INT UNSIGNED NOT NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    DATETIME     NOT NULL,
    source_ip     VARBINARY(16) DEFAULT NULL,
    user_agent    VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_user (user_id),
    CONSTRAINT fk_sess_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Append-only (§15.7). Grant the app INSERT/SELECT only — no UPDATE/DELETE.
CREATE TABLE audit_log (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_user_id INT UNSIGNED    DEFAULT NULL,
    action        VARCHAR(64)     NOT NULL,
    target        VARCHAR(255)    DEFAULT NULL,
    detail_json   JSON            DEFAULT NULL,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_ip     VARBINARY(16)   DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_actor (actor_user_id),
    KEY idx_action_time (action, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Ingestion bookkeeping — supports the §8 heartbeat / dead-man's-switch
-- ---------------------------------------------------------------------------
CREATE TABLE ingest_runs (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    started_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at    DATETIME     DEFAULT NULL,
    messages_seen  INT UNSIGNED NOT NULL DEFAULT 0,
    reports_stored INT UNSIGNED NOT NULL DEFAULT 0,
    failures       INT UNSIGNED NOT NULL DEFAULT 0,
    status         ENUM('running','ok','error') NOT NULL DEFAULT 'running',
    detail         TEXT         DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_started (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Per-sender rate limiting (§4.1) — caps how many messages a single sender
-- can push through ingestion per time window, independent of the overall
-- batch_limit, so one hostile/misbehaving sender can't monopolize a run.
-- ---------------------------------------------------------------------------
CREATE TABLE ingest_sender_counters (
    sender        VARCHAR(255) NOT NULL,
    window_start  DATETIME     NOT NULL,
    message_count INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (sender, window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
