<?php

declare(strict_types=1);

/**
 * Front controller (spec §7). Apache DocumentRoot points here.
 * All routing goes through this file — no direct script access.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Auth\AuditLog;
use App\Auth\Csrf;
use App\Auth\InvitationService;
use App\Auth\LoginRateLimiter;
use App\Auth\Mailer;
use App\Auth\PasswordHasher;
use App\Auth\PasswordResetService;
use App\Auth\RecoveryCodes;
use App\Auth\Roles;
use App\Auth\SealedCookie;
use App\Auth\SessionManager;
use App\Auth\StepUp;
use App\Auth\TotpService;
use App\Auth\UserRepository;
use App\Auth\WebauthnCredentialStore;
use App\Auth\WebauthnService;
use App\Config;
use App\Database;
use App\HealthCheck\HealthCheckRepository;
use App\HealthCheck\HealthCheckRunnerFactory;
use App\Http\AuthMiddleware;
use App\Http\Controllers\AdminUsersController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DomainController;
use App\Http\Controllers\InviteController;
use App\Http\Controllers\PasswordResetController;
use App\Http\Controllers\SecurityController;
use App\Http\Router;
use App\Recommendation\RecommendationRepository;

// Security headers. No inline <script>/<style> is used anywhere (see
// public/assets/) so the CSP stays strict with no 'unsafe-inline'.
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'");

$config = Config::load();
$pdo = Database::connect($config);

$baseUrl = (string) $config->require('app.base_url');
$secureCookie = str_starts_with($baseUrl, 'https://');

if ($secureCookie) {
    header('Strict-Transport-Security: max-age=63072000; includeSubDomains');
}

$hasher = new PasswordHasher();
$totp = new TotpService((string) $config->require('app.totp_encryption_key'));
$recoveryCodes = new RecoveryCodes($hasher);
$recoveryCodesCount = (int) $config->get('app.recovery_codes_count', 10);
$users = new UserRepository($pdo);
$csrf = new Csrf((string) $config->require('app.csrf_secret'));
$sealed = new SealedCookie((string) $config->require('app.cookie_seal_secret'), $secureCookie);
$sessions = new SessionManager(
    $pdo,
    (string) $config->get('app.session_cookie_name', 'dmarc_session'),
    (int) $config->get('app.session_idle_minutes', 30),
    (int) $config->get('app.session_absolute_hours', 12),
    $secureCookie,
);
$stepUp = new StepUp($hasher, $sealed);
$audit = new AuditLog($pdo);
$mailer = new Mailer((string) $config->require('app.mail_from'));
$invitations = new InvitationService($pdo, $users, (int) $config->get('app.invitation_ttl_hours', 168));
$resets = new PasswordResetService($pdo, $users, (int) $config->get('app.password_reset_ttl_minutes', 60));
$webauthn = new WebauthnService(
    (string) $config->require('app.webauthn_rp_id'),
    (string) $config->require('app.webauthn_rp_name'),
    $baseUrl,
);
$webauthnStore = new WebauthnCredentialStore($pdo);

$auth = new AuthMiddleware($sessions, $users, $csrf);
$rateLimiter = new LoginRateLimiter($pdo);

$authController = new AuthController(
    $pdo, $users, $hasher, $totp, $recoveryCodes, $sessions, $webauthn, $webauthnStore, $sealed, $audit, $auth, $rateLimiter,
);
$inviteController = new InviteController(
    $pdo, $users, $invitations, $hasher, $totp, $recoveryCodes, $recoveryCodesCount,
    $sessions, $webauthn, $webauthnStore, $sealed, $audit,
);
$resetController = new PasswordResetController($resets, $hasher, $mailer, $sessions, $audit, $baseUrl);
$securityController = new SecurityController(
    $pdo, $users, $hasher, $totp, $recoveryCodes, $recoveryCodesCount,
    $sessions, $webauthn, $webauthnStore, $sealed, $stepUp, $audit, $auth,
);
$adminController = new AdminUsersController(
    $pdo, $users, $invitations, $resets, $mailer, $sessions, $stepUp, $audit, $auth, $baseUrl,
);
$healthCheckRepository = new HealthCheckRepository($pdo);
$domainController      = new DomainController(
    $pdo,
    new RecommendationRepository($pdo),
    $healthCheckRepository,
    new HealthCheckRunnerFactory($config, $healthCheckRepository),
    $audit,
    $auth,
    $stepUp,
);

$router = new Router();

$router->get('/healthz', static function (): void {
    header('Content-Type: application/json');
    echo json_encode(['status' => 'ok'], JSON_THROW_ON_ERROR);
});

// --- Login / logout -------------------------------------------------------
$router->get('/login', [$authController, 'showLogin']);
$router->post('/login', [$authController, 'login']);
$router->get('/login/totp', [$authController, 'showTotp']);
$router->post('/login/totp', [$authController, 'verifyTotp']);
$router->post('/login/passkey/options', [$authController, 'passkeyOptions']);
$router->post('/login/passkey/verify', [$authController, 'passkeyVerify']);
$router->post('/logout', $auth->guardPost(Roles::READ_ONLY, static fn () => $authController->logout()));

// --- Invitation acceptance --------------------------------------------------
$router->get('/invite', [$inviteController, 'showAccept']);
$router->post('/invite/accept-password', [$inviteController, 'startPassword']);
$router->get('/invite/totp-setup', [$inviteController, 'showTotpSetup']);
$router->post('/invite/totp-confirm', [$inviteController, 'confirmTotp']);
$router->post('/invite/accept-passkey/options', [$inviteController, 'passkeyOptions']);
$router->post('/invite/accept-passkey/verify', [$inviteController, 'passkeyVerify']);

// --- Password reset ---------------------------------------------------------
$router->get('/password-reset', [$resetController, 'showRequest']);
$router->post('/password-reset', [$resetController, 'request']);
$router->get('/password-reset/confirm', [$resetController, 'showConfirm']);
$router->post('/password-reset/confirm', [$resetController, 'confirm']);

// --- Self-service account/security (spec §15.4) ----------------------------
$router->get('/account/security', $auth->guard(Roles::READ_ONLY, [$securityController, 'show']));
$router->post('/account/password', $auth->guardPost(Roles::READ_ONLY, [$securityController, 'changePassword']));
$router->get('/account/totp/enroll', $auth->guard(Roles::READ_ONLY, [$securityController, 'showTotpEnroll']));
$router->post('/account/totp/confirm', $auth->guardPost(Roles::READ_ONLY, [$securityController, 'confirmTotpEnroll']));
$router->post('/account/totp/remove', $auth->guardPost(Roles::READ_ONLY, [$securityController, 'removeTotp']));
$router->post('/account/recovery-codes/regenerate', $auth->guardPost(Roles::READ_ONLY, [$securityController, 'regenerateRecoveryCodes']));
$router->post('/account/passkeys/register/options', $auth->guardPost(Roles::READ_ONLY, [$securityController, 'passkeyRegisterOptions']));
$router->post('/account/passkeys/register/verify', $auth->guardPost(Roles::READ_ONLY, [$securityController, 'passkeyRegisterVerify']));
$router->post('/account/passkeys/remove', $auth->guardPost(Roles::READ_ONLY, [$securityController, 'removePasskey']));
$router->post('/account/stepup/passkey/options', $auth->guardPost(Roles::READ_ONLY, [$securityController, 'stepUpOptions']));
$router->post('/account/stepup/passkey/verify', $auth->guardPost(Roles::READ_ONLY, [$securityController, 'stepUpVerify']));

// --- Super-admin user management (spec §15.1/§15.5) -------------------------
$router->get('/admin/users', $auth->guard(Roles::SUPER_ADMIN, [$adminController, 'list']));
$router->post('/admin/users/invite', $auth->guardPost(Roles::SUPER_ADMIN, [$adminController, 'invite']));
$router->post('/admin/users/reinvite', $auth->guardPost(Roles::SUPER_ADMIN, [$adminController, 'reinvite']));
$router->post('/admin/users/role', $auth->guardPost(Roles::SUPER_ADMIN, [$adminController, 'changeRole']));
$router->post('/admin/users/disable', $auth->guardPost(Roles::SUPER_ADMIN, [$adminController, 'disable']));
$router->post('/admin/users/enable', $auth->guardPost(Roles::SUPER_ADMIN, [$adminController, 'enable']));
$router->post('/admin/users/delete', $auth->guardPost(Roles::SUPER_ADMIN, [$adminController, 'delete']));
$router->post('/admin/users/password-reset', $auth->guardPost(Roles::SUPER_ADMIN, [$adminController, 'triggerPasswordReset']));
$router->post('/admin/users/reset-mfa', $auth->guardPost(Roles::SUPER_ADMIN, [$adminController, 'resetMfa']));
$router->post('/admin/users/revoke-sessions', $auth->guardPost(Roles::SUPER_ADMIN, [$adminController, 'revokeSessions']));

// --- Dashboard (spec §7.1/§7.2/§7.3 — every view requires at least read-only) ---
$router->get('/', $auth->guard(Roles::READ_ONLY, [$domainController, 'index']));
$router->get('/domain', $auth->guard(Roles::READ_ONLY, [$domainController, 'show']));
$router->get('/domain/report', $auth->guard(Roles::READ_ONLY, [$domainController, 'reportDetail']));

// --- Domain onboarding / baseline approval / policy editing (spec §10.6/§11.1/§15.1 — Admin tier) ---
$router->post('/domains/add', $auth->guardPost(Roles::ADMIN, [$domainController, 'add']));
$router->post('/domain/approve-baseline', $auth->guardPost(Roles::ADMIN, [$domainController, 'approveBaseline']));
$router->post('/domain/policy', $auth->guardPost(Roles::ADMIN, [$domainController, 'updatePolicy']));

// --- Domain removal/reactivation (spec §15.1/§15.3 — Super-admin tier, step-up) ---
$router->post('/domain/deactivate', $auth->guardPost(Roles::SUPER_ADMIN, [$domainController, 'deactivate']));
$router->post('/domain/reactivate', $auth->guardPost(Roles::SUPER_ADMIN, [$domainController, 'reactivate']));

$router->dispatch(
    $_SERVER['REQUEST_METHOD'] ?? 'GET',
    parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/'
);
