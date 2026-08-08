<?php

declare(strict_types=1);

namespace App\Http;

use App\Auth\AuthUser;
use App\Auth\Csrf;
use App\Auth\Roles;
use App\Auth\SessionManager;
use App\Auth\UserRepository;

/**
 * Resolves the current user from the session cookie once per request and
 * wraps route handlers with role checks. Deny-by-default (spec §15.6): a
 * route registered via guard() rejects unauthenticated/under-privileged
 * requests before the handler ever runs; routes registered directly on the
 * Router (login, invite-accept, password-reset, healthz) are the only
 * public ones, and that has to be a deliberate choice at registration time,
 * not something a handler can get wrong.
 */
final class AuthMiddleware
{
    private bool $resolved  = false;
    private ?AuthUser $user = null;

    public function __construct(
        private readonly SessionManager $sessions,
        private readonly UserRepository $users,
        private readonly Csrf $csrf,
    ) {
    }

    public function currentUser(): ?AuthUser
    {
        if ($this->resolved) {
            return $this->user;
        }

        $this->resolved = true;
        $session        = $this->sessions->current();

        if ($session === null) {
            return null;
        }

        $user = $this->users->findById($session->userId);

        if ($user === null || !$user->isActive()) {
            $this->sessions->destroy();

            return null;
        }

        return $this->user = $user;
    }

    /** CSRF token for the current session — embed in every authenticated POST form. */
    public function csrfToken(): ?string
    {
        $session = $this->sessions->current();

        return $session === null ? null : $this->csrf->token($session->token);
    }

    /** @param callable(AuthUser): void $handler */
    public function guard(string $minRole, callable $handler): callable
    {
        return function () use ($minRole, $handler): void {
            $user = $this->currentUser();

            if ($user === null) {
                header('Location: /login');

                return;
            }

            if (!Roles::atLeast($user->role, $minRole)) {
                http_response_code(403);
                header('Content-Type: text/plain');
                echo "Forbidden\n";

                return;
            }

            $handler($user);
        };
    }

    /**
     * Same as guard(), plus a CSRF synchronizer-token check on $_POST —
     * use for every authenticated state-changing route.
     *
     * @param callable(AuthUser): void $handler
     */
    public function guardPost(string $minRole, callable $handler): callable
    {
        return $this->guard($minRole, function (AuthUser $user) use ($handler): void {
            $session   = $this->sessions->current();
            $submitted = $_POST['csrf_token'] ?? '';

            if ($session === null || !\is_string($submitted) || !$this->csrf->verify($session->token, $submitted)) {
                http_response_code(400);
                header('Content-Type: text/plain');
                echo "Invalid or missing CSRF token\n";

                return;
            }

            $handler($user);
        });
    }
}
