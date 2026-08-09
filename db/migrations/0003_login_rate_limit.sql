-- ---------------------------------------------------------------------------
-- Login rate limiting (F-04, spec §15).
--
-- Tracks failed authentication attempts per source IP over a sliding window.
-- Keyed on (ip, window_start) with a fixed window width (e.g. 5 minutes).
-- Separate from ingest_sender_counters — different threat model and lifecycle.
-- ---------------------------------------------------------------------------
CREATE TABLE login_rate_limit (
    ip           VARBINARY(16)  NOT NULL,           -- INET6_ATON() for v4/v6 uniformity
    window_start DATETIME       NOT NULL,
    attempt_count INT UNSIGNED  NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, window_start),
    KEY idx_window_start (window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
