<?php

declare(strict_types=1);

/**
 * bin/create-superadmin.php — Bootstrap the first super_admin account.
 *
 * Issues an invitation link for the given email address with the super_admin
 * role. No existing user needs to exist to act as the inviter — InvitationService
 * accepts a null invited_by for exactly this bootstrapping case.
 *
 * Usage:
 *   php bin/create-superadmin.php user@example.com
 *
 * The invitation link is printed to stdout. Send it to the user; it is never
 * stored in plain text and cannot be recovered after this script exits.
 *
 * Running this script a second time for the same email invalidates the
 * previous (unconsumed) invitation and issues a fresh one.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Auth\InvitationService;
use App\Auth\Roles;
use App\Auth\UserRepository;
use App\Config;
use App\Database;

// ── argument validation ───────────────────────────────────────────────────────

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script must be run from the command line.\n");
    exit(1);
}

$email = $argv[1] ?? '';

if ($email === '' || !str_contains($email, '@')) {
    fwrite(STDERR, "Usage: php bin/create-superadmin.php <email>\n");
    exit(1);
}

// ── bootstrap ─────────────────────────────────────────────────────────────────

$config = Config::load();
$pdo    = Database::connect($config);

$users       = new UserRepository($pdo);
$invitations = new InvitationService(
    $pdo,
    $users,
    (int) $config->get('app.invitation_ttl_hours', 168),
);

// ── issue invitation ──────────────────────────────────────────────────────────

try {
    // invited_by is null — allowed by the schema and InvitationService for
    // the bootstrap case where no actor yet exists.
    $token   = $invitations->issue($email, Roles::SUPER_ADMIN, invitedByUserId: null);
    $baseUrl = rtrim((string) $config->get('app.base_url', ''), '/');
    $link    = $baseUrl . '/accept-invite?token=' . urlencode($token);

    echo "Super-admin invitation issued for: {$email}\n";
    echo "Invitation link (valid for {$config->get('app.invitation_ttl_hours', 168)} hours):\n\n";
    echo "  {$link}\n\n";
    echo "Send this link to the user. It cannot be recovered once this script exits.\n";
} catch (\App\Auth\AuthException $e) {
    fwrite(STDERR, "Error: {$e->getMessage()}\n");
    exit(1);
}
