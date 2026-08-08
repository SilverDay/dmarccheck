-- Seed the ten managed domains (spec §16 item 2).
-- target_policy defaults to full enforcement; approved_baseline_policy is
-- intentionally left NULL — it must be set by an explicit admin
-- "approve as baseline" action after the first health check (§11.1), not
-- silently copied from whatever DNS happens to say today.

INSERT INTO domains (domain, target_policy, non_sending, active) VALUES
    ('silverday.de',     'p=reject; sp=reject', 0, 1),
    ('tourl.at',         'p=reject; sp=reject', 0, 1),
    ('roya.at',          'p=reject; sp=reject', 0, 1),
    ('gcgtc.com',        'p=reject; sp=reject', 0, 1),
    ('dagatal.de',       'p=reject; sp=reject', 0, 1),
    ('threatforge.de',   'p=reject; sp=reject', 0, 1),
    ('clearstats.de',    'p=reject; sp=reject', 0, 1),
    ('kioju.de',         'p=reject; sp=reject', 0, 1),
    ('wizardscastle.de', 'p=reject; sp=reject', 0, 1),
    ('wanyanka.de',      'p=reject; sp=reject', 0, 1)
ON DUPLICATE KEY UPDATE domain = VALUES(domain);
