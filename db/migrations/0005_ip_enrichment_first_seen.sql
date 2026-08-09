-- Overview dashboard (spec §7.1) "newly seen unknown senders" needs to know
-- when an IP was first observed, not just most recently. Existing rows keep
-- first_seen = NULL — backfilling from last_seen would fabricate a
-- first-observation time that was never actually recorded.

ALTER TABLE ip_enrichment ADD COLUMN first_seen DATETIME DEFAULT NULL AFTER label;
