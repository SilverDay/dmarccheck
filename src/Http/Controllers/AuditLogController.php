<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\AuditLog;
use App\Auth\AuthUser;
use App\Http\AuthMiddleware;
use App\Http\View;

/**
 * Super Admin-only read-only view of `audit_log` (spec §15.7) — no
 * mutations here, matching AuditLog's own append-only, no-delete-method
 * design. Gated at Super Admin rather than Admin: the log's contents
 * skew toward user-account governance (invites, role changes, MFA
 * resets), all of which are already Super-Admin-only actions via
 * AdminUsersController.
 */
final class AuditLogController
{
    private const int LIMIT = 200;

    public function __construct(
        private readonly AuditLog $audit,
        private readonly AuthMiddleware $auth,
    ) {
    }

    public function list(AuthUser $user): void
    {
        $actionPrefix = isset($_GET['action_prefix']) && $_GET['action_prefix'] !== ''
            ? (string) $_GET['action_prefix']
            : null;

        $entries = $this->audit->recent(self::LIMIT, $actionPrefix !== null ? $actionPrefix . '%' : null);

        $rows = '';

        foreach ($entries as $entry) {
            $actor  = $entry->actorEmail ?? ($entry->actorUserId !== null ? '#' . $entry->actorUserId : 'system');
            $detail = $entry->detail === [] ? '' : '<code class="rec-evidence">' . View::e(json_encode($entry->detail, JSON_THROW_ON_ERROR)) . '</code>';

            $rows .= sprintf(
                '<tr><td class="mono">%s</td><td>%s</td><td class="mono">%s</td><td>%s</td><td class="mono">%s</td><td>%s</td></tr>',
                View::e($entry->createdAt),
                View::e($actor),
                View::e($entry->action),
                View::e($entry->target ?? '—'),
                View::e($entry->sourceIp ?? '—'),
                $detail,
            );
        }

        $body = '<div class="page-head"><div><h1>Audit log</h1>'
            . '<div class="sub">Most recent ' . \count($entries) . ' entr' . (\count($entries) === 1 ? 'y' : 'ies') . ' &middot; super admin only</div></div></div>';

        $body .= '<div class="narrow" style="margin-bottom:0;"><form method="get" action="/admin/audit-log" class="inline-form" style="gap:8px;">'
            . '<input type="text" name="action_prefix" placeholder="Filter by action prefix, e.g. domain." value="' . View::e($actionPrefix ?? '') . '">'
            . '<button type="submit" class="btn btn-secondary btn-sm">Filter</button>'
            . ($actionPrefix !== null ? '<a href="/admin/audit-log" class="btn btn-secondary btn-sm">Clear</a>' : '')
            . '</form></div>';

        $body .= '<div class="table-card"><div class="table-scroll"><table><thead><tr>'
            . '<th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Source IP</th><th>Detail</th>'
            . '</tr></thead><tbody>' . ($rows !== '' ? $rows : '<tr><td colspan="6" class="empty">No matching entries.</td></tr>') . '</tbody></table></div></div>';

        View::render('Audit log', $body, $user, $this->auth->csrfToken());
    }
}
