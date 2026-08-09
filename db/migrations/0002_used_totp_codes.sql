-- ---------------------------------------------------------------------------
-- TOTP replay protection (F-02, spec §15.3).
--
-- Records the TOTP period counter (floor(time() / step)) for each user
-- after a successful verification so the same code cannot be accepted again
-- within the leeway window. Rows are pruned to (leeway * 2 + 1) step-widths
-- worth of retention — they have no value beyond that since the TOTP
-- counter for that period can never be valid again.
-- ---------------------------------------------------------------------------
CREATE TABLE used_totp_codes (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED    NOT NULL,
    period      BIGINT UNSIGNED NOT NULL,          -- floor(unix_timestamp / step)
    used_at     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_period (user_id, period),   -- one row per (user, period) — enforces replay rejection at DB level too
    KEY idx_used_at (used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
