-- TLS-RPT extension (spec §3.7, §12) — RFC 8460 JSON reports.
-- Mirrors the reports/report_records split, but flattened one row per
-- (domain, policy-type): unlike DMARC XML (one file = one domain), an
-- RFC 8460 JSON file's `policies[]` array can name multiple domains.

SET NAMES utf8mb4;

CREATE TABLE tls_rpt_reports (
    id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id         INT UNSIGNED NOT NULL,
    organization_name VARCHAR(255) NOT NULL,
    report_id         VARCHAR(255) NOT NULL,
    date_begin        DATETIME NOT NULL,
    date_end          DATETIME NOT NULL,
    policy_type       ENUM('sts','tlsa','no-policy-found') NOT NULL,
    policy_string     TEXT DEFAULT NULL,   -- policy-string[] lines, newline-joined
    mx_host           TEXT DEFAULT NULL,   -- policy.mx-host patterns, newline-joined
    success_count     INT UNSIGNED NOT NULL DEFAULT 0,
    failure_count     INT UNSIGNED NOT NULL DEFAULT 0,
    -- SHA-256 of decompressed JSON — NOT unique (one file -> many rows, one
    -- per matched domain/policy); alreadyIngested() existence-checks it.
    raw_file_hash     CHAR(64) NOT NULL,
    received_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_tls_rpt_report (domain_id, report_id, policy_type),
    KEY idx_domain_range (domain_id, date_begin),
    KEY idx_hash (raw_file_hash),
    CONSTRAINT fk_tls_rpt_reports_domain FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE tls_rpt_records (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tls_rpt_report_id       BIGINT UNSIGNED NOT NULL,
    result_type             VARCHAR(64) NOT NULL,   -- not ENUM: IANA registry grows
    sending_mta_ip          VARBINARY(16) DEFAULT NULL,
    receiving_mx_hostname   VARCHAR(255) DEFAULT NULL,
    receiving_mx_helo       VARCHAR(255) DEFAULT NULL,
    receiving_ip            VARBINARY(16) DEFAULT NULL,
    failed_session_count    INT UNSIGNED NOT NULL DEFAULT 0,
    additional_information  VARCHAR(512) DEFAULT NULL,
    failure_reason_code     VARCHAR(128) DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_tls_rpt_report (tls_rpt_report_id),
    CONSTRAINT fk_tls_rpt_records_report FOREIGN KEY (tls_rpt_report_id) REFERENCES tls_rpt_reports (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
