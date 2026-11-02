-- Cross-domain report search filters by report-period start date without a
-- domain_id predicate. The existing (domain_id, date_begin) key cannot serve
-- that range independently.
ALTER TABLE reports
    ADD KEY idx_report_date_begin (date_begin);
