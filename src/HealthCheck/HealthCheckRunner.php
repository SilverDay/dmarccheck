<?php

declare(strict_types=1);

namespace App\HealthCheck;

use App\HealthCheck\Checks\HealthCheck;

/**
 * Runs an ordered list of checks against one domain, persisting every item
 * and updating domains.current_published_policy from the DMARC check's
 * result (spec §11.1). One check throwing (a bug, an unexpected network
 * failure) never aborts the rest — turned into a single `error` item for
 * that check instead, same resilience posture as bin/ingest.php.
 */
final class HealthCheckRunner
{
    /** @param list<HealthCheck> $checks */
    public function __construct(
        private readonly array $checks,
        private readonly HealthCheckRepository $repository,
    ) {
    }

    /** @return list<HealthCheckItemResult> everything recorded, for the caller to summarize */
    public function run(int $domainId, string $domain, string $trigger): array
    {
        $checkId  = $this->repository->startRun($domainId, $trigger);
        $allItems = [];

        foreach ($this->checks as $check) {
            foreach ($this->runOne($check, $domain) as $item) {
                $this->repository->recordItem($checkId, $item);
                $allItems[] = $item;

                if ($item->checkName === 'dmarc') {
                    $policyString = $item->detail['policy_string'] ?? null;

                    if (\is_string($policyString) && $policyString !== '') {
                        $this->repository->updatePublishedPolicy($domainId, $policyString);
                    }
                }
            }
        }

        return $allItems;
    }

    /** @return list<HealthCheckItemResult> */
    private function runOne(HealthCheck $check, string $domain): array
    {
        try {
            return $check->run($domain);
        } catch (\Throwable $e) {
            return [new HealthCheckItemResult('unknown', $check::class, HealthCheckItemResult::ERROR, [
                'reason' => 'check threw an exception: ' . $e->getMessage(),
            ])];
        }
    }
}
