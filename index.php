<?php
/**
 * Wessling Familienarchiv — Auslieferung mit Zugriffsprotokoll.
 *
 * Diese Datei liefert die unveraenderte Archivdatei (index.html) aus und
 * notiert vorher einen Eintrag im Logbuch. Die Archivdatei selbst wird
 * dabei nicht angefasst — kuenftige Aktualisierungen funktionieren wie bisher.
 */

declare(strict_types=1);

$archiv = __DIR__ . '/index.html';

// Protokollieren; darf die Auslieferung unter keinen Umstaenden stoeren.
try {
    $lib = __DIR__ . '/wfa-log/lib.php';
    if (is_file($lib)) {
        require_once $lib;
        $pfad = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
        wfa_protokollieren(is_string($pfad) && $pfad !== '' ? $pfad : '/');
    }
} catch (\Throwable $e) {
    // stillschweigend uebergehen
}

if (!is_file($archiv)) {
    http_response_code(500);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><meta charset="utf-8"><title>Archiv</title>'
       . '<p style="font-family:Georgia,serif;margin:3rem">Die Archivdatei wurde nicht gefunden.</p>';
    exit;
}

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Referrer-Policy: no-referrer');
header('Content-Length: ' . (string) filesize($archiv));

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'HEAD') {
    exit;
}

readfile($archiv);
