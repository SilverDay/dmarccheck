-- RFC 9990 aggregate-report additions (DMARCbis, docs/feature-dmarcbis.md
-- Phase 1, §3.1.1.x): report-level generator/discovery method, and
-- per-record envelope identifiers. All nullable — absent on every
-- classic-era report, which is the normal case for years yet.
ALTER TABLE reports ADD COLUMN generator VARCHAR(255) DEFAULT NULL AFTER raw_file_hash;
ALTER TABLE reports ADD COLUMN discovery_method VARCHAR(16) DEFAULT NULL AFTER generator;

ALTER TABLE report_records ADD COLUMN envelope_from VARCHAR(255) DEFAULT NULL AFTER header_from;
ALTER TABLE report_records ADD COLUMN envelope_to VARCHAR(255) DEFAULT NULL AFTER envelope_from;
