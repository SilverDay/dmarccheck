<?php

declare(strict_types=1);

namespace App\Http;

/**
 * Minimal front-controller router — no framework, per the project's
 * stack conventions.
 *
 * NOTE (spec §15.6): authorization is deny-by-default and must be enforced
 * server-side inside each handler (or via middleware added here) — never by
 * hiding UI controls. Route registration alone grants nothing.
 */
final class Router
{
    /** @var array<string, array<string, callable>> */
    private array $routes = ['GET' => [], 'POST' => []];

    public function get(string $path, callable $handler): void
    {
        $this->routes['GET'][$path] = $handler;
    }

    public function post(string $path, callable $handler): void
    {
        $this->routes['POST'][$path] = $handler;
    }

    public function dispatch(string $method, string $path): void
    {
        $path    = rtrim($path, '/') ?: '/';
        $handler = $this->routes[strtoupper($method)][$path] ?? null;

        if ($handler === null) {
            http_response_code(404);
            header('Content-Type: text/plain');
            echo "Not found\n";

            return;
        }

        $handler();
    }
}
