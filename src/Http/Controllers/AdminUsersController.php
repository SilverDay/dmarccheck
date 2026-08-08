<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\AuditLog;
use App\Auth\AuthException;
use App\Auth\AuthUser;
use App\Auth\InvitationService;
use App\Auth\Mailer;
use App\Auth\PasswordResetService;
use App\Auth\Roles;
use App\Auth\SessionManager;
use App\Auth\StepUp;
use App\Auth\UserRepository;
use App\Http\AuthMiddleware;
use App\Http\View;
use PDO;

/**
 * Super-admin-only user management (spec §15.1/§15.5). Every action here
 * requires the actor's step-up auth and is audit-logged — both enforced
 * uniformly via requireStepUp() below. UserRepository is what actually
 * enforces "at least one active super admin must always exist"; this
 * controller just surfaces the AuthException it throws.
 */
final class AdminUsersController
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly UserRepository $users,
        private readonly InvitationService $invitations,
        private readonly PasswordResetService $resets,
        private readonly Mailer $mailer,
        private readonly SessionManager $sessions,
        private readonly StepUp $stepUp,
        private readonly AuditLog $audit,
        private readonly AuthMiddleware $auth,
        private readonly string $baseUrl,
    ) {
    }

    public function list(AuthUser $actor): void
    {
        $this->renderList($actor);
    }

    public function invite(AuthUser $actor): void
    {
        if (!$this->requireStepUp($actor)) {
            return;
        }

        $email = trim((string) ($_POST['email'] ?? ''));
        $role  = (string) ($_POST['role'] ?? Roles::READ_ONLY);

        try {
            $token = $this->invitations->issue($email, $role, $actor->id);
        } catch (AuthException $e) {
            $this->renderList($actor, error: $e->getMessage());

            return;
        }

        $this->sendInviteEmail($email, $token);
        $this->audit->record($actor->id, 'user.invited', $email, ['role' => $role], $this->clientIp());
        $this->renderList($actor, flash: "Invitation sent to {$email}.");
    }

    public function reinvite(AuthUser $actor): void
    {
        if (!$this->requireStepUp($actor)) {
            return;
        }

        $user = $this->targetUser();

        if ($user === null || $user->status !== 'invited') {
            $this->renderList($actor, error: 'That user cannot be re-invited.');

            return;
        }

        $token = $this->invitations->issue($user->email, $user->role, $actor->id);
        $this->sendInviteEmail($user->email, $token);
        $this->audit->record($actor->id, 'user.reinvited', $user->email, [], $this->clientIp());
        $this->renderList($actor, flash: "Invitation resent to {$user->email}.");
    }

    public function changeRole(AuthUser $actor): void
    {
        if (!$this->requireStepUp($actor)) {
            return;
        }

        $user = $this->targetUser();
        $role = (string) ($_POST['role'] ?? '');

        if ($user === null || !Roles::isValid($role)) {
            $this->renderList($actor, error: 'Invalid request.');

            return;
        }

        try {
            $this->users->updateRole($user->id, $role);
        } catch (AuthException $e) {
            $this->renderList($actor, error: $e->getMessage());

            return;
        }

        $this->audit->record($actor->id, 'user.role_changed', $user->email, ['role' => $role], $this->clientIp());
        $this->renderList($actor, flash: "Role updated for {$user->email}.");
    }

    public function disable(AuthUser $actor): void
    {
        if (!$this->requireStepUp($actor)) {
            return;
        }

        $user = $this->targetUser();

        if ($user === null) {
            $this->renderList($actor, error: 'User not found.');

            return;
        }

        try {
            $this->users->disable($user->id);
        } catch (AuthException $e) {
            $this->renderList($actor, error: $e->getMessage());

            return;
        }

        $this->sessions->destroyAllForUser($user->id);
        $this->audit->record($actor->id, 'user.disabled', $user->email, [], $this->clientIp());
        $this->renderList($actor, flash: "{$user->email} disabled.");
    }

    public function enable(AuthUser $actor): void
    {
        if (!$this->requireStepUp($actor)) {
            return;
        }

        $user = $this->targetUser();

        if ($user === null) {
            $this->renderList($actor, error: 'User not found.');

            return;
        }

        $this->users->enable($user->id);
        $this->audit->record($actor->id, 'user.enabled', $user->email, [], $this->clientIp());
        $this->renderList($actor, flash: "{$user->email} re-enabled.");
    }

    public function delete(AuthUser $actor): void
    {
        if (!$this->requireStepUp($actor)) {
            return;
        }

        $user = $this->targetUser();

        if ($user === null) {
            $this->renderList($actor, error: 'User not found.');

            return;
        }

        try {
            $this->users->delete($user->id);
        } catch (AuthException $e) {
            $this->renderList($actor, error: $e->getMessage());

            return;
        }

        $this->audit->record($actor->id, 'user.deleted', $user->email, [], $this->clientIp());
        $this->renderList($actor, flash: "{$user->email} deleted.");
    }

    /** Same mechanism as self-service (§15.5) — the admin never sets or sees the password. */
    public function triggerPasswordReset(AuthUser $actor): void
    {
        if (!$this->requireStepUp($actor)) {
            return;
        }

        $user = $this->targetUser();

        if ($user === null) {
            $this->renderList($actor, error: 'User not found.');

            return;
        }

        $token = $this->resets->request($user->email);

        if ($token !== null) {
            $link = rtrim($this->baseUrl, '/') . '/password-reset/confirm?token=' . urlencode($token);
            $this->mailer->send(
                $user->email,
                'Your DMARC Analyzer password was reset by an administrator',
                "Use this link to set a new password (expires shortly):\n\n{$link}"
            );
        }

        $this->audit->record($actor->id, 'user.password_reset_triggered', $user->email, [], $this->clientIp());
        $this->renderList($actor, flash: "Password reset link sent to {$user->email}.");
    }

    /**
     * Clears every credential and MFA factor and routes the user back
     * through invitation acceptance — the same re-enrollment path a brand
     * new user takes — since this app has no separate "keep the password,
     * only reset MFA" flow. The user cannot sign in until they complete it
     * (spec §15.5: "force the user to re-enrol a factor at next login").
     */
    public function resetMfa(AuthUser $actor): void
    {
        if (!$this->requireStepUp($actor)) {
            return;
        }

        $user   = $this->targetUser();
        $reason = trim((string) ($_POST['reason'] ?? ''));

        if ($user === null || $reason === '') {
            $this->renderList($actor, error: 'A reason is required to reset MFA.');

            return;
        }

        $this->pdo->prepare('DELETE FROM webauthn_credentials WHERE user_id = ?')->execute([$user->id]);
        $this->pdo->prepare('DELETE FROM recovery_codes WHERE user_id = ?')->execute([$user->id]);
        $this->pdo->prepare("UPDATE users SET credential_hash = NULL, totp_secret = NULL, status = 'invited' WHERE id = ?")
            ->execute([$user->id]);
        $this->sessions->destroyAllForUser($user->id);

        $token = $this->invitations->issue($user->email, $user->role, $actor->id);
        $this->sendInviteEmail($user->email, $token);

        $this->audit->record($actor->id, 'user.mfa_reset', $user->email, ['reason' => $reason], $this->clientIp());
        $this->renderList($actor, flash: "MFA cleared for {$user->email} — a new invitation was sent to re-enroll.");
    }

    public function revokeSessions(AuthUser $actor): void
    {
        if (!$this->requireStepUp($actor)) {
            return;
        }

        $user = $this->targetUser();

        if ($user === null) {
            $this->renderList($actor, error: 'User not found.');

            return;
        }

        $this->sessions->destroyAllForUser($user->id);
        $this->audit->record($actor->id, 'user.sessions_revoked', $user->email, [], $this->clientIp());
        $this->renderList($actor, flash: "Sessions revoked for {$user->email}.");
    }

    private function requireStepUp(AuthUser $actor): bool
    {
        if ($this->stepUp->verify($actor)) {
            return true;
        }

        $this->renderList($actor, error: 'Please re-verify (current password or passkey) to perform this action.');

        return false;
    }

    private function targetUser(): ?AuthUser
    {
        $id = (int) ($_POST['user_id'] ?? 0);

        return $id > 0 ? $this->users->findById($id) : null;
    }

    private function sendInviteEmail(string $email, string $token): void
    {
        $link = rtrim($this->baseUrl, '/') . '/invite?token=' . urlencode($token);
        $this->mailer->send(
            $email,
            'You have been invited to DMARC Analyzer',
            "You've been invited to DMARC Analyzer. Set up your account:\n\n{$link}"
        );
    }

    private function renderList(AuthUser $actor, ?string $flash = null, ?string $error = null): void
    {
        $csrf        = $this->auth->csrfToken();
        $stepUpField = $this->stepUp->fieldHtml($actor);

        $rows = implode('', array_map(function (AuthUser $u) use ($actor, $csrf, $stepUpField): string {
            return $this->userRow($u, $actor, $csrf, $stepUpField);
        }, $this->users->all()));

        $body = '<h1>Users</h1>';

        if ($flash !== null) {
            $body .= '<p class="flash">' . View::e($flash) . '</p>';
        }

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        $body .= '<table><tr><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr>' . $rows . '</table>'
            . '<h2>Invite a user</h2>'
            . '<form method="post" action="/admin/users/invite" class="stack">'
            . View::csrfField($csrf) . $stepUpField
            . '<p><label for="email">Email</label><input type="email" id="email" name="email" required></p>'
            . '<p><label for="role">Role</label><select id="role" name="role">'
            . '<option value="' . Roles::READ_ONLY . '">Read-only</option>'
            . '<option value="' . Roles::ADMIN . '">Admin</option>'
            . '<option value="' . Roles::SUPER_ADMIN . '">Super admin</option>'
            . '</select></p>'
            . '<p><button type="submit">Send invitation</button></p>'
            . '</form>';

        View::render('Users', $body, $actor, $csrf, $flash);
    }

    private function userRow(AuthUser $u, AuthUser $actor, ?string $csrf, string $stepUpField): string
    {
        $idField   = '<input type="hidden" name="user_id" value="' . $u->id . '">';
        $csrfField = View::csrfField($csrf);
        $actions   = [];

        if ($u->status === 'invited') {
            $actions[] = $this->actionForm('/admin/users/reinvite', 'Re-invite', $idField, $csrfField, $stepUpField);
        }

        if ($u->status === 'active') {
            $actions[] = $this->actionForm('/admin/users/disable', 'Disable', $idField, $csrfField, $stepUpField);
            $actions[] = $this->actionForm('/admin/users/password-reset', 'Send password reset', $idField, $csrfField, $stepUpField);
            $actions[] = $this->actionForm(
                '/admin/users/reset-mfa',
                'Reset MFA',
                $idField,
                $csrfField,
                $stepUpField . '<p><label>Reason<input type="text" name="reason" required></label></p>'
            );
            $actions[] = $this->actionForm('/admin/users/revoke-sessions', 'Force logout', $idField, $csrfField, $stepUpField);
        }

        if ($u->status === 'disabled') {
            $actions[] = $this->actionForm('/admin/users/enable', 'Re-enable', $idField, $csrfField, $stepUpField);
        }

        if ($u->id !== $actor->id) {
            $actions[] = $this->actionForm('/admin/users/delete', 'Delete', $idField, $csrfField, $stepUpField);
        }

        $roleForm = '<form method="post" action="/admin/users/role" class="inline">'
            . $idField . $csrfField . $stepUpField
            . '<select name="role">'
            . '<option value="' . Roles::READ_ONLY . '"' . ($u->role === Roles::READ_ONLY ? ' selected' : '') . '>Read-only</option>'
            . '<option value="' . Roles::ADMIN . '"' . ($u->role === Roles::ADMIN ? ' selected' : '') . '>Admin</option>'
            . '<option value="' . Roles::SUPER_ADMIN . '"' . ($u->role === Roles::SUPER_ADMIN ? ' selected' : '') . '>Super admin</option>'
            . '</select> <button type="submit">Update role</button></form>';

        return '<tr><td>' . View::e($u->email) . '</td>'
            . '<td>' . $roleForm . '</td>'
            . '<td>' . View::e($u->status) . '</td>'
            . '<td>' . implode(' ', $actions) . '</td></tr>';
    }

    private function actionForm(string $action, string $label, string $idField, string $csrfField, string $stepUpField): string
    {
        return '<form method="post" action="' . View::e($action) . '" class="inline">'
            . $idField . $csrfField . $stepUpField
            . '<button type="submit">' . View::e($label) . '</button></form>';
    }

    private function clientIp(): ?string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;

        return \is_string($ip) && $ip !== '' ? $ip : null;
    }
}
