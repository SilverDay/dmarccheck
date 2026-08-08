<?php

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()
    ->in([__DIR__ . '/src', __DIR__ . '/bin', __DIR__ . '/tests']);

return (new PhpCsFixer\Config())
    ->setRules([
        '@PSR12'                 => true,
        'declare_strict_types'   => true,
        'ordered_imports'        => ['sort_algorithm' => 'alpha'],
        'no_unused_imports'      => true,
        'trailing_comma_in_multiline' => true,
        'binary_operator_spaces' => ['default' => 'align_single_space_minimal'],
    ])
    ->setRiskyAllowed(true)
    ->setFinder($finder);
