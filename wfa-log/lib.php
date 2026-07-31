<?php
/**
 * Wessling Familienarchiv — Zugriffsprotokoll
 * Nachschlagen von Land und Internetanbieter aus der IP-Adresse
 * sowie Schreiben und Lesen des Logbuchs.
 *
 * Es werden keinerlei Daten an Dritte gesendet: Die Zuordnung geschieht
 * ausschliesslich anhand der mitgelieferten Tabellen im Ordner data/.
 */

declare(strict_types=1);

const WFA_DIR       = __DIR__;
const WFA_DATA      = __DIR__ . '/data';
const WFA_LOGDIR    = __DIR__ . '/log';
const WFA_CONFIG    = __DIR__ . '/config.php';
const WFA_GUARD     = "<?php http_response_code(404); exit; ?>\n";
const WFA_SESSIONGAP = 1800;   // Sekunden: danach zaehlt ein Aufruf als neuer Besuch

/* ------------------------------------------------------------------ *
 *  Einstellungen
 * ------------------------------------------------------------------ */

function wfa_config(bool $neu_laden = false): array
{
    static $cfg = null;
    if ($cfg !== null && !$neu_laden) {
        return $cfg;
    }
    $defaults = [
        'passwort_hash'  => '',
        'salt'           => '',
        'zeitzone'       => 'Europe/Berlin',
        'ip_speichern'   => 'gekuerzt',   // gekuerzt | nein | voll
        'aufbewahrung'   => 24,           // Monate; 0 = unbegrenzt
    ];
    $cfg = $defaults;
    if (is_file(WFA_CONFIG)) {
        $geladen = @include WFA_CONFIG;
        if (is_array($geladen)) {
            $cfg = array_merge($defaults, $geladen);
        }
    }
    return $cfg;
}

function wfa_config_speichern(array $neu): bool
{
    $cfg = array_merge(wfa_config(), $neu);
    $code = "<?php\n// Automatisch erzeugt — Einstellungen des Zugriffsprotokolls.\nreturn "
          . var_export($cfg, true) . ";\n";
    $ok = @file_put_contents(WFA_CONFIG, $code, LOCK_EX) !== false;
    if ($ok) {
        @chmod(WFA_CONFIG, 0640);
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate(WFA_CONFIG, true);
        }
        wfa_config(true);          // zwischengespeicherte Einstellungen auffrischen
    }
    return $ok;
}

function wfa_eingerichtet(): bool
{
    $cfg = wfa_config();
    return $cfg['passwort_hash'] !== '';
}

/* ------------------------------------------------------------------ *
 *  Binaere Suche in den Nachschlagetabellen
 * ------------------------------------------------------------------ */

/**
 * Sucht den Datensatz, dessen Bereich den Schluessel enthaelt.
 * Die Datei besteht aus gleich langen Datensaetzen  start|ende|nutzlast,
 * aufsteigend sortiert; start und ende sind Big-Endian-Zahlen, sodass
 * ein einfacher Byte-Vergleich (strcmp) der Zahlenordnung entspricht.
 */
function wfa_bereich_suchen(string $datei, int $satzlaenge, int $schluessellaenge, string $schluessel): ?string
{
    if (!is_file($datei)) {
        return null;
    }
    $groesse = filesize($datei);
    if ($groesse === false || $groesse < $satzlaenge) {
        return null;
    }
    $anzahl = intdiv($groesse, $satzlaenge);
    $fh = @fopen($datei, 'rb');
    if (!$fh) {
        return null;
    }
    $treffer = null;
    $lo = 0;
    $hi = $anzahl - 1;
    while ($lo <= $hi) {
        $mitte = intdiv($lo + $hi, 2);
        fseek($fh, $mitte * $satzlaenge);
        $satz = fread($fh, $satzlaenge);
        if ($satz === false || strlen($satz) < $satzlaenge) {
            break;
        }
        if (strcmp(substr($satz, 0, $schluessellaenge), $schluessel) <= 0) {
            $treffer = $satz;
            $lo = $mitte + 1;
        } else {
            $hi = $mitte - 1;
        }
    }
    fclose($fh);
    if ($treffer === null) {
        return null;
    }
    $ende = substr($treffer, $schluessellaenge, $schluessellaenge);
    if (strcmp($schluessel, $ende) > 0) {
        return null;            // liegt in einer Luecke zwischen zwei Bereichen
    }
    return substr($treffer, 2 * $schluessellaenge);
}

function wfa_ip_schluessel(string $ip): ?array
{
    $roh = @inet_pton($ip);
    if ($roh === false) {
        return null;
    }
    if (strlen($roh) === 4) {
        return ['v4', $roh, 4];
    }
    if (strlen($roh) === 16) {
        return ['v6', substr($roh, 0, 8), 8];   // obere 64 Bit genuegen fuer Land und Anbieter
    }
    return null;
}

function wfa_land_zu_ip(string $ip): string
{
    $s = wfa_ip_schluessel($ip);
    if ($s === null) {
        return '';
    }
    [$art, $schluessel, $len] = $s;
    $datei = WFA_DATA . ($art === 'v4' ? '/country-v4.bin' : '/country-v6.bin');
    $wert  = wfa_bereich_suchen($datei, 2 * $len + 2, $len, $schluessel);
    if ($wert === null) {
        return '';
    }
    $cc = strtoupper(trim($wert));
    return preg_match('/^[A-Z]{2}$/', $cc) ? $cc : '';
}

function wfa_anbieter_zu_ip(string $ip): string
{
    $s = wfa_ip_schluessel($ip);
    if ($s === null) {
        return '';
    }
    [$art, $schluessel, $len] = $s;
    $datei = WFA_DATA . ($art === 'v4' ? '/asn-v4.bin' : '/asn-v6.bin');
    $wert  = wfa_bereich_suchen($datei, 2 * $len + 4, $len, $schluessel);
    if ($wert === null || strlen($wert) < 4) {
        return '';
    }
    $entpackt = unpack('Noffset', $wert);
    $offset   = $entpackt['offset'] ?? null;
    if ($offset === null) {
        return '';
    }
    $namen = WFA_DATA . '/asn-names.bin';
    $fh = @fopen($namen, 'rb');
    if (!$fh) {
        return '';
    }
    fseek($fh, $offset);
    $stueck = fread($fh, 96);
    fclose($fh);
    if ($stueck === false) {
        return '';
    }
    $pos = strpos($stueck, "\n");
    return $pos === false ? '' : substr($stueck, 0, $pos);
}

/** Deutscher Landesname; faellt auf eine kleine eigene Liste bzw. das Kuerzel zurueck. */
function wfa_landesname(string $cc): string
{
    if ($cc === '') {
        return 'unbekannt';
    }
    if (class_exists('Locale')) {
        $name = @Locale::getDisplayRegion('-' . $cc, 'de');
        if (is_string($name) && $name !== '' && strtoupper($name) !== $cc) {
            return $name;
        }
    }
    static $tab = [
        'DE' => 'Deutschland', 'PL' => 'Polen', 'AT' => 'Österreich', 'CH' => 'Schweiz',
        'NL' => 'Niederlande', 'BE' => 'Belgien', 'FR' => 'Frankreich', 'GB' => 'Vereinigtes Königreich',
        'IE' => 'Irland', 'DK' => 'Dänemark', 'SE' => 'Schweden', 'NO' => 'Norwegen',
        'FI' => 'Finnland', 'IT' => 'Italien', 'ES' => 'Spanien', 'PT' => 'Portugal',
        'CZ' => 'Tschechien', 'SK' => 'Slowakei', 'HU' => 'Ungarn', 'RO' => 'Rumänien',
        'HR' => 'Kroatien', 'SI' => 'Slowenien', 'LT' => 'Litauen', 'LV' => 'Lettland',
        'EE' => 'Estland', 'UA' => 'Ukraine', 'RU' => 'Russland', 'BY' => 'Belarus',
        'US' => 'USA', 'CA' => 'Kanada', 'MX' => 'Mexiko', 'BR' => 'Brasilien',
        'AR' => 'Argentinien', 'AU' => 'Australien', 'NZ' => 'Neuseeland', 'IL' => 'Israel',
        'TR' => 'Türkei', 'GR' => 'Griechenland', 'ZA' => 'Südafrika', 'IN' => 'Indien',
        'CN' => 'China', 'JP' => 'Japan', 'KR' => 'Südkorea', 'SG' => 'Singapur',
        'LU' => 'Luxemburg', 'BG' => 'Bulgarien', 'RS' => 'Serbien', 'IS' => 'Island',
    ];
    return $tab[$cc] ?? $cc;
}

/* ------------------------------------------------------------------ *
 *  Besucherangaben aus der Anfrage
 * ------------------------------------------------------------------ */

function wfa_client_ip(): string
{
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP'] as $kopf) {
        if (!empty($_SERVER[$kopf]) && filter_var($_SERVER[$kopf], FILTER_VALIDATE_IP)) {
            return $_SERVER[$kopf];
        }
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        foreach (explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $teil) {
            $teil = trim($teil);
            if (filter_var($teil, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $teil;
            }
        }
    }
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
}

function wfa_ip_kuerzen(string $ip, string $modus): string
{
    if ($ip === '' || $modus === 'nein') {
        return '';
    }
    if ($modus === 'voll') {
        return $ip;
    }
    if (strpos($ip, ':') !== false) {
        $teile = explode(':', $ip);
        return implode(':', array_slice($teile, 0, 2)) . ':…';
    }
    $teile = explode('.', $ip);
    return count($teile) === 4 ? $teile[0] . '.' . $teile[1] . '.x.x' : '';
}

/** Sehr einfache Auswertung der Browserkennung — bewusst grob gehalten. */
function wfa_geraet(string $ua): array
{
    $ua_l = strtolower($ua);
    $bot = (bool) preg_match('/bot|crawl|spider|slurp|curl|wget|python-requests|headless|monitor|preview|scan/i', $ua);

    $geraet = 'Rechner';
    if (preg_match('/ipad|tablet/i', $ua)) {
        $geraet = 'Tablet';
    } elseif (preg_match('/mobile|iphone|android|phone/i', $ua)) {
        $geraet = 'Handy';
    }

    $system = 'unbekannt';
    foreach ([
        'Windows' => 'windows nt', 'iOS' => 'iphone|ipad|ipod', 'macOS' => 'mac os x',
        'Android' => 'android', 'Linux' => 'linux',
    ] as $name => $muster) {
        if (preg_match('~' . $muster . '~i', $ua_l)) { $system = $name; break; }
    }

    $browser = 'unbekannt';
    foreach ([
        'Edge' => 'edg/', 'Opera' => 'opr/|opera', 'Samsung' => 'samsungbrowser',
        'Chrome' => 'chrome|crios', 'Firefox' => 'firefox|fxios', 'Safari' => 'safari',
    ] as $name => $muster) {
        if (preg_match('~' . $muster . '~i', $ua_l)) { $browser = $name; break; }
    }
    if ($bot) {
        $geraet = 'Bot';
    }
    return [$geraet, $system, $browser, $bot];
}

function wfa_sprache(): string
{
    $roh = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    if ($roh === '') {
        return '';
    }
    $erste = trim(explode(',', $roh)[0]);
    $erste = explode(';', $erste)[0];
    return substr(preg_replace('/[^A-Za-z\-]/', '', $erste), 0, 8);
}

/* ------------------------------------------------------------------ *
 *  Schreiben
 * ------------------------------------------------------------------ */

function wfa_logdatei(string $monat): string
{
    return WFA_LOGDIR . '/zugriffe-' . $monat . '.log.php';
}

function wfa_feld(string $wert): string
{
    return str_replace(["\t", "\r", "\n"], ' ', trim($wert));
}

/**
 * Protokolliert den aktuellen Aufruf. Wirft nie eine Ausnahme nach aussen —
 * die Auslieferung der Website darf davon niemals abhaengen.
 */
function wfa_protokollieren(string $seite = '/'): void
{
    try {
        $cfg = wfa_config();
        @date_default_timezone_set($cfg['zeitzone']);

        if (!is_dir(WFA_LOGDIR)) {
            @mkdir(WFA_LOGDIR, 0750, true);
        }
        $schutz = WFA_LOGDIR . '/.htaccess';
        if (!is_file($schutz)) {
            @file_put_contents($schutz, "Require all denied\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n");
        }

        $ip  = wfa_client_ip();
        $ua  = substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 400);
        $cc  = $ip !== '' ? wfa_land_zu_ip($ip) : '';
        $anb = $ip !== '' ? wfa_anbieter_zu_ip($ip) : '';
        [$geraet, $system, $browser, $bot] = wfa_geraet($ua);

        if ($cfg['salt'] === '') {
            wfa_config_speichern(['salt' => bin2hex(random_bytes(16))]);
            $cfg = wfa_config(true);
        }
        $kennung = substr(hash('sha256', $cfg['salt'] . '|' . $ip . '|' . $ua), 0, 10);

        $zeile = implode("\t", array_map('wfa_feld', [
            date('Y-m-d H:i:s'),
            $kennung,
            $cc,
            $anb,
            $geraet,
            $system,
            $browser,
            wfa_sprache(),
            wfa_ip_kuerzen($ip, (string) $cfg['ip_speichern']),
            $bot ? '1' : '0',
            $seite,
        ])) . "\n";

        $datei = wfa_logdatei(date('Y-m'));
        if (!is_file($datei)) {
            @file_put_contents($datei, WFA_GUARD, LOCK_EX);
            @chmod($datei, 0640);
        }
        @file_put_contents($datei, $zeile, FILE_APPEND | LOCK_EX);

        if ((int) $cfg['aufbewahrung'] > 0 && random_int(1, 50) === 1) {
            wfa_aufraeumen((int) $cfg['aufbewahrung']);
        }
    } catch (\Throwable $e) {
        // bewusst stillschweigend: das Protokoll darf die Website nicht stoeren
    }
}

function wfa_aufraeumen(int $monate): void
{
    $grenze = date('Y-m', strtotime('-' . $monate . ' months'));
    foreach (glob(WFA_LOGDIR . '/zugriffe-*.log.php') ?: [] as $datei) {
        if (preg_match('/zugriffe-(\d{4}-\d{2})\.log\.php$/', $datei, $m) && $m[1] < $grenze) {
            @unlink($datei);
        }
    }
}

/* ------------------------------------------------------------------ *
 *  Lesen und Auswerten
 * ------------------------------------------------------------------ */

function wfa_monate(): array
{
    $monate = [];
    foreach (glob(WFA_LOGDIR . '/zugriffe-*.log.php') ?: [] as $datei) {
        if (preg_match('/zugriffe-(\d{4}-\d{2})\.log\.php$/', $datei, $m)) {
            $monate[] = $m[1];
        }
    }
    rsort($monate);
    return $monate;
}

function wfa_eintraege(string $monat): array
{
    $datei = wfa_logdatei($monat);
    if (!is_file($datei)) {
        return [];
    }
    $zeilen = @file($datei, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $felder = ['zeit', 'kennung', 'cc', 'anbieter', 'geraet', 'system', 'browser', 'sprache', 'ip', 'bot', 'seite'];
    $out = [];
    foreach ($zeilen as $zeile) {
        if ($zeile === '' || $zeile[0] === '<') {
            continue;                       // Schutzzeile am Dateianfang
        }
        $teile = explode("\t", $zeile);
        if (count($teile) < 3) {
            continue;
        }
        $eintrag = [];
        foreach ($felder as $i => $name) {
            $eintrag[$name] = $teile[$i] ?? '';
        }
        $eintrag['bot'] = ($eintrag['bot'] === '1');
        $eintrag['land'] = wfa_landesname($eintrag['cc']);
        $eintrag['ts'] = strtotime($eintrag['zeit']) ?: 0;
        $out[] = $eintrag;
    }
    return $out;
}

/** Fasst aufeinanderfolgende Aufrufe desselben Besuchers zu einem Besuch zusammen. */
function wfa_besuche(array $eintraege): array
{
    usort($eintraege, fn($a, $b) => $a['ts'] <=> $b['ts']);
    $besuche = [];
    $offen = [];
    foreach ($eintraege as $e) {
        $k = $e['kennung'];
        if (isset($offen[$k]) && ($e['ts'] - $besuche[$offen[$k]]['ende']) <= WFA_SESSIONGAP) {
            $b = &$besuche[$offen[$k]];
            $b['ende'] = $e['ts'];
            $b['aufrufe']++;
            unset($b);
        } else {
            $besuche[] = [
                'beginn'   => $e['ts'],
                'ende'     => $e['ts'],
                'aufrufe'  => 1,
                'kennung'  => $k,
                'cc'       => $e['cc'],
                'land'     => $e['land'],
                'anbieter' => $e['anbieter'],
                'geraet'   => $e['geraet'],
                'system'   => $e['system'],
                'browser'  => $e['browser'],
                'sprache'  => $e['sprache'],
                'ip'       => $e['ip'],
                'bot'      => $e['bot'],
            ];
            $offen[$k] = count($besuche) - 1;
        }
    }
    usort($besuche, fn($a, $b) => $b['beginn'] <=> $a['beginn']);
    return $besuche;
}

function wfa_dauer(int $sekunden): string
{
    if ($sekunden < 60) {
        return $sekunden . ' Sek.';
    }
    $min = intdiv($sekunden, 60);
    if ($min < 60) {
        return $min . ' Min.';
    }
    return intdiv($min, 60) . ' Std. ' . ($min % 60) . ' Min.';
}
