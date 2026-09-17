<?php
require_once __DIR__ . '/../config/config.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function is_logged_in(): bool
{
    return isset($_SESSION['user_id']);
}

function current_user_id()
{
    return $_SESSION['user_id'] ?? null;
}

function require_login(): void
{
    if (!is_logged_in()) {
        header('Location: login.php');
        exit;
    }
}

/**
 * HTML-escape helper used by the SECURE pages. Vulnerable pages deliberately
 * skip this so their output can be exploited.
 */
function e(?string $s): string
{
    return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8');
}
