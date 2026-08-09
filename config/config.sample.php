<?php

declare(strict_types=1);

/**
 * Copy to config/config.php and fill in. config.php is gitignored.
 *
 * Per spec §16, the alert address, GeoLite2 key and Spamhaus DQS key are
 * intended to be editable from the web UI; this file holds the bootstrap
 * values and DB connection needed before the app can read its own settings.
 */

return [
    'db' => [
        'dsn'      => 'mysql:host=127.0.0.1;dbname=dmarc;charset=utf8mb4',
        'user'     => 'dmarc',
        'password' => '',
    ],

    'imap' => [
        // §4 — webklex/php-imap. Native ext/imap is unbundled+unmaintained (PHP 8.4).
        'host'           => 'localhost',
        'port'           => 993,
        'protocol'       => 'imap',
        'encryption'     => 'ssl',
        'validate_cert'  => true,
        'username'       => 'dmarc-reports@silverday.de',
        'password'       => '',
        'folder_inbox'   => 'INBOX',
        'folder_done'    => 'INBOX.Processed',
        'folder_failed'  => 'INBOX.Failed',
    ],

    // §4.1 — hostile-input caps. The rua address is published in DNS, so
    // anything on the internet can submit to it. These are hard limits.
    'ingest' => [
        'max_attachment_bytes'   => 10 * 1024 * 1024,   // pre-decompression, per attachment
        'max_message_bytes'      => 20 * 1024 * 1024,   // pre-decompression, summed across a message's attachments
        'max_decompressed_bytes' => 50 * 1024 * 1024,   // decompression-bomb ceiling
        'max_zip_entries'        => 16,
        'archive_path'           => __DIR__ . '/../archive',
        'batch_limit'            => 200,                 // messages per run

        // §4.1 — per-sender volume cap, independent of batch_limit, so one
        // sender can't monopolize a run or flood the mailbox.
        'rate_limit' => [
            'window_minutes' => 60,
            'max_messages'   => 50,
        ],
    ],

    'enrichment' => [
        // Local DB avoids per-query third-party disclosure (§14)
        'geolite2_asn_db' => __DIR__ . '/../var/GeoLite2-ASN.mmdb',
        // Unused by bin/enrich.php itself — reserved for a future geoipupdate-style
        // DB refresh mechanism (§6: "refresh DB monthly" is an ops task, not this script's job).
        'maxmind_key' => '',

        'batch_limit'  => 500,  // IPs processed per run, mirrors ingest.batch_limit
        'refresh_days' => 30,   // re-enrich IPs older than this, not just brand-new ones

        // §6 — ASN-based heuristic label, the fallback tier below known_senders and
        // above unknown. Deliberately small and conservative: only ASNs we're
        // confident about, since a wrong number silently mislabels real traffic.
        // Starting point for an admin to extend, not an authoritative database.
        'known_esp_asns' => [
            15169 => 'Google',
            8075  => 'Microsoft',
            16509 => 'Amazon AWS',
        ],
    ],

    'healthcheck' => [
        // §11.6 — free DQS key required; public mirrors block non-attributable
        // resolvers and return 127.255.255.254. Register:
        // https://www.spamhaus.com/free-trial/free-trial-for-data-query-service/
        'spamhaus_dqs_key' => '',
        'resolver'         => '127.0.0.1',
        'dkim_selectors'   => ['default', 'mail', 'google', 'selector1', 'selector2', 'k1', 's1', 's2'],

        // §11.4 — keep every network probe lightweight and bounded.
        'smtp_timeout_seconds' => 5,
        'http_timeout_seconds' => 5,
        'dig_timeout_seconds'  => 5,

        // §11.6 — DQS keyed zone hostnames. Verify against current Spamhaus
        // DQS documentation before relying on this in production; not
        // hardcoded into DnsblCheck so it can be corrected without a code change.
        'dnsbl_zones' => [
            'zen' => 'zen.dqs.spamhaus.net',
            'dbl' => 'dbl.dqs.spamhaus.net',
        ],
    ],

    'alerting' => [
        'to'                  => 'security@silverday.de',
        'from'                => 'dmarc-analyzer@silverday.de',
        'heartbeat_days'      => 3,      // §8 dead-man's-switch
        'unknown_ip_volume'   => 50,
        'pass_rate_drop_pct'  => 10,

        'window_days'             => 1,   // "recent" day-over-day window for volume + pass-rate checks
        'pass_rate_baseline_days' => 30,  // trailing window the recent pass rate is compared against
        'pass_rate_min_count'     => 50,  // minimum sample size, both windows, before judging a pass-rate drop
    ],

    // §10 — R1-R12 rule engine. Reuses alerting.unknown_ip_volume for R5/R6
    // rather than a duplicate threshold.
    'recommendation' => [
        'window_days'           => 7,   // R1-R5, R7, R8, R10, R11
        'sustained_window_days' => 30,  // R6
        'sustained_min_days'    => 3,   // distinct report days required within the sustained window
    ],

    // §10.8 — ships disabled; gate stays closed until the T&C + GDPR
    // review is recorded. Manual, human-reviewed submissions only.
    'community_reporting' => [
        'enabled'        => false,
        'review_recorded'=> false,
        'api_key'        => '',
    ],

    'app' => [
        'base_url'     => 'https://dmarc.silverday.de',
        'session_idle_minutes'     => 30,
        'session_absolute_hours'   => 12,
        // §15.3 — WebAuthn relying party
        'webauthn_rp_id'   => 'dmarc.silverday.de',
        'webauthn_rp_name' => 'DMARC Analyzer',

        // §15 auth — generate with: php -r "echo bin2hex(random_bytes(32));"
        // HMAC key for CSRF synchronizer tokens. Never reuse for encryption.
        'app_secret' => '',

        // §15.8 — encrypts users.totp_secret at rest. Generate with:
        // php -r "echo base64_encode(sodium_crypto_secretbox_keygen());"
        'totp_encryption_key' => '',

        'session_cookie_name'         => 'dmarc_session',
        'invitation_ttl_hours'        => 168,
        'password_reset_ttl_minutes'  => 60,
        'recovery_codes_count'        => 10,

        // §15.2/§15.4 — invite/reset emails, sent via PHP mail() (local MTA)
        'mail_from' => 'dmarc-analyzer@silverday.de',
    ],
];
