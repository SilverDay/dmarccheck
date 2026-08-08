<?php

declare(strict_types=1);

namespace App;

use PDO;

final class Database
{
    private static ?PDO $pdo = null;

    public static function connect(Config $config): PDO
    {
        if (self::$pdo instanceof PDO) {
            return self::$pdo;
        }

        self::$pdo = new PDO(
            (string) $config->require('db.dsn'),
            (string) $config->require('db.user'),
            (string) $config->get('db.password', ''),
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                // Real prepared statements, not client-side interpolation.
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );

        return self::$pdo;
    }
}
