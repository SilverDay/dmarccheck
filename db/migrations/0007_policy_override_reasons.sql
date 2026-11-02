-- RFC 9990 §3.1.6 policy_evaluated/reason data, including policy_test_mode.
ALTER TABLE report_records
    ADD COLUMN policy_override_reasons JSON DEFAULT NULL AFTER envelope_to;
