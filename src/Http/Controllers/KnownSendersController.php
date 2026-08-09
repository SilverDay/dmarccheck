<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\AuditLog;
use App\Auth\AuthUser;
use App\Http\AuthMiddleware;
use App\Http\View;
use App\Support\Ip;
use PDO;

/**
 * Admin-tier CRUD for `known_senders` (spec §3.6/§10.5/§15.1 — "edit
 * allowlists" is an Admin capability, no step-up: not in spec §15.3's
 * step-up list, same reasoning already applied to DomainController's
 * add()/approveBaseline()/updatePolicy()). Add/delete only — no update
 * form, since editing a rule is delete-then-re-add. `domain_id = NULL`
 * means the rule applies to every domain (§3.6); rules take effect the
 * next time KnownSenderMatcher::fromDatabase() is called (bin/enrich.php,
 * bin/analyze.php) — this controller only writes the table.
 */
final class KnownSendersController
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly AuditLog $audit,
        private readonly AuthMiddleware $auth,
    ) {
    }

    public function list(AuthUser $user): void
    {
        $this->renderList($user);
    }

    public function add(AuthUser $actor): void
    {
        $ipOrCidr = trim((string) ($_POST['ip_or_cidr'] ?? ''));
        $label    = trim((string) ($_POST['label'] ?? ''));
        $domainId = (int) ($_POST['domain_id'] ?? 0);

        if (!Ip::isValidIpOrCidr($ipOrCidr)) {
            $this->renderList($actor, error: 'Enter a valid IP address or CIDR range.');

            return;
        }

        if ($label === '') {
            $this->renderList($actor, error: 'A label is required.');

            return;
        }

        // 0/absent means global — otherwise the domain must actually exist
        // and be active, so a stale/crafted POST can't FK-violate into a 500.
        if ($domainId !== 0) {
            $stmt = $this->pdo->prepare('SELECT 1 FROM domains WHERE id = ? AND active = 1');
            $stmt->execute([$domainId]);

            if ($stmt->fetchColumn() === false) {
                $this->renderList($actor, error: 'Choose a valid domain, or "All domains".');

                return;
            }
        }

        $this->pdo->prepare('INSERT INTO known_senders (domain_id, ip_or_cidr, label) VALUES (?, ?, ?)')
            ->execute([$domainId !== 0 ? $domainId : null, $ipOrCidr, $label]);

        $this->audit->record($actor->id, 'known_sender.added', $ipOrCidr, [
            'label'     => $label,
            'domain_id' => $domainId !== 0 ? $domainId : null,
        ], $this->clientIp());

        $this->renderList($actor, flash: "Added \"$ipOrCidr\" to the allowlist.");
    }

    public function delete(AuthUser $actor): void
    {
        $id = (int) ($_POST['id'] ?? 0);

        $stmt = $this->pdo->prepare('SELECT ip_or_cidr FROM known_senders WHERE id = ?');
        $stmt->execute([$id]);
        $ipOrCidr = $stmt->fetchColumn();

        if ($ipOrCidr === false) {
            $this->renderList($actor, error: 'Allowlist entry not found.');

            return;
        }

        $this->pdo->prepare('DELETE FROM known_senders WHERE id = ?')->execute([$id]);
        $this->audit->record($actor->id, 'known_sender.removed', (string) $ipOrCidr, [], $this->clientIp());

        $this->renderList($actor, flash: "Removed \"$ipOrCidr\" from the allowlist.");
    }

    private function renderList(AuthUser $user, ?string $flash = null, ?string $error = null): void
    {
        $csrf = $this->auth->csrfToken();

        $rules = $this->pdo->query(
            'SELECT ks.id, ks.domain_id, d.domain, ks.ip_or_cidr, ks.label, ks.created_at
               FROM known_senders ks
               LEFT JOIN domains d ON d.id = ks.domain_id
              ORDER BY d.domain IS NULL DESC, d.domain, ks.id'
        )->fetchAll();

        $rows = '';

        foreach ($rules as $rule) {
            $domainLabel = $rule['domain'] !== null ? View::e((string) $rule['domain']) : View::badge('neutral', 'All domains');

            $rows .= sprintf(
                '<tr><td>%s</td><td class="mono">%s</td><td>%s</td><td class="mono">%s</td><td class="actions-cell">%s</td></tr>',
                $domainLabel,
                View::e((string) $rule['ip_or_cidr']),
                View::e((string) $rule['label']),
                View::e((string) $rule['created_at']),
                '<form method="post" action="/admin/known-senders/delete" class="inline-form">'
                    . View::csrfField($csrf)
                    . '<input type="hidden" name="id" value="' . (int) $rule['id'] . '">'
                    . '<button type="submit" class="btn btn-sm btn-danger">Delete</button></form>'
            );
        }

        $body = '<div class="page-head"><div><h1>Allowlist' . View::helpTooltip('page-allowlist', 'What this page is for') . '</h1>'
            . '<div class="sub">' . \count($rules) . ' known-sender rule' . (\count($rules) === 1 ? '' : 's') . ' &middot; admin only</div></div></div>';

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        $body .= '<div class="table-card"><div class="table-scroll"><table><thead><tr>'
            . '<th>Domain</th><th>IP / CIDR</th><th>Label</th><th>Added</th><th>Actions</th>'
            . '</tr></thead><tbody>' . ($rows !== '' ? $rows : '<tr><td colspan="5" class="empty">No allowlist rules yet.</td></tr>') . '</tbody></table></div></div>';

        $domainOptions = '<option value="0">All domains</option>';

        foreach ($this->activeDomains() as $domain) {
            $domainOptions .= '<option value="' . (int) $domain['id'] . '">' . View::e((string) $domain['domain']) . '</option>';
        }

        $body .= '<div class="narrow narrow-tight"><div class="card">'
            . '<h2>Add allowlist rule</h2>'
            . '<form method="post" action="/admin/known-senders/add">'
            . View::csrfField($csrf)
            . '<div class="field"><label for="domain_id">Domain</label><select id="domain_id" name="domain_id">' . $domainOptions . '</select></div>'
            . '<div class="field"><label for="ip_or_cidr">IP or CIDR</label><input type="text" id="ip_or_cidr" name="ip_or_cidr" placeholder="203.0.113.0/24" required></div>'
            . '<div class="field"><label for="label">Label</label><input type="text" id="label" name="label" placeholder="SMTP relay" required></div>'
            . '<button type="submit" class="btn btn-primary btn-block">Add rule</button>'
            . '</form></div></div>';

        $body .= '<script src="/assets/help.js"></script>';

        View::render('Allowlist', $body, $user, $csrf, $flash);
    }

    /** @return list<array{id: int, domain: string}> */
    private function activeDomains(): array
    {
        return $this->pdo->query('SELECT id, domain FROM domains WHERE active = 1 ORDER BY domain')->fetchAll();
    }

    private function clientIp(): ?string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;

        return \is_string($ip) && $ip !== '' ? $ip : null;
    }
}
