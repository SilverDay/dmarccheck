<?php

declare(strict_types=1);

/**
 * bin/analyze.php — spec §10. The R1-R12 rule engine: aggregates report
 * data + enrichment + a live SPF lookup check into recommendations,
 * auto-resolving ones whose trigger no longer fires. Advisory only — never
 * edits DNS/mail config itself (spec §10.7).
 *
 *   php bin/analyze.php                # every active domain
 *   php bin/analyze.php example.com     # one domain
 *
 * 30   4 * * *  php /srv/dmarc/bin/analyze.php >> /var/log/dmarc-analyze.log 2>&1
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Config;
use App\Database;
use App\HealthCheck\SystemDnsResolver;
use App\Recommendation\AnalysisContextBuilder;
use App\Recommendation\RecommendationReconciler;
use App\Recommendation\RecommendationRepository;
use App\Recommendation\Rules\R10Rule;
use App\Recommendation\Rules\R11Rule;
use App\Recommendation\Rules\R12Rule;
use App\Recommendation\Rules\R1Rule;
use App\Recommendation\Rules\R2Rule;
use App\Recommendation\Rules\R3Rule;
use App\Recommendation\Rules\R4Rule;
use App\Recommendation\Rules\R5Rule;
use App\Recommendation\Rules\R6Rule;
use App\Recommendation\Rules\R7Rule;
use App\Recommendation\Rules\R8Rule;
use App\Recommendation\Rules\R9Rule;
use App\Recommendation\Rules\Rule;

$config = Config::load();
$pdo    = Database::connect($config);

$windowDays          = (int) $config->get('recommendation.window_days', 7);
$sustainedWindowDays = (int) $config->get('recommendation.sustained_window_days', 30);
$sustainedMinDays    = (int) $config->get('recommendation.sustained_min_days', 3);
$volumeThreshold     = (int) $config->get('alerting.unknown_ip_volume', 50);

$contextBuilder = new AnalysisContextBuilder(
    $pdo,
    new SystemDnsResolver(),
    $windowDays,
    $sustainedWindowDays,
    $sustainedMinDays,
);
$repository = new RecommendationRepository($pdo);
$reconciler = new RecommendationReconciler();

/** @var list<Rule> $rules */
$rules = [
    new R1Rule(),
    new R2Rule(),
    new R3Rule(),
    new R4Rule(),
    new R5Rule($volumeThreshold),
    new R6Rule($volumeThreshold),
    new R7Rule(),
    new R8Rule(),
    new R9Rule(),
    new R10Rule(),
    new R11Rule(),
    new R12Rule(),
];

$domainArg = $argv[1] ?? null;

if ($domainArg !== null) {
    $stmt = $pdo->prepare('SELECT id, domain FROM domains WHERE domain = ? AND active = 1');
    $stmt->execute([strtolower($domainArg)]);
} else {
    $stmt = $pdo->query('SELECT id, domain FROM domains WHERE active = 1 ORDER BY domain');
}

$domains = $stmt->fetchAll();

if ($domains === []) {
    fwrite(STDERR, "No matching active domain(s) found.\n");
    exit(1);
}

foreach ($domains as $row) {
    $domainId = (int) $row['id'];
    $domain   = (string) $row['domain'];

    try {
        $context = $contextBuilder->build($domainId, $domain);

        $findings = [];
        foreach ($rules as $rule) {
            $findings = [...$findings, ...$rule->evaluate($context)];
        }

        $existing   = $repository->openAndAcknowledged($domainId);
        $suppressed = $repository->suppressedSubjects($domainId);
        $plan       = $reconciler->plan($findings, $existing, $suppressed);

        foreach ($plan->toInsert as $finding) {
            $repository->insert($domainId, $finding);
        }

        foreach ($plan->toTouch as $touch) {
            $repository->touch($touch['id'], $touch['finding']);
        }

        foreach ($plan->toResolve as $id) {
            $repository->resolve($id);
        }

        printf(
            "[ok] %s — %d new, %d ongoing, %d resolved\n",
            $domain,
            \count($plan->toInsert),
            \count($plan->toTouch),
            \count($plan->toResolve)
        );
    } catch (Throwable $e) {
        fwrite(STDERR, "[fail] $domain: " . $e->getMessage() . "\n");
    }
}

exit(0);
