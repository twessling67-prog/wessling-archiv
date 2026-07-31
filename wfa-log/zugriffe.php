<?php
/**
 * Wessling Familienarchiv — Admin-Ansicht des Zugriffsprotokolls.
 * Aufruf:  https://wessling-family.com/wfa-log/zugriffe.php
 */

declare(strict_types=1);
require_once __DIR__ . '/lib.php';

$cfg = wfa_config();
@date_default_timezone_set($cfg['zeitzone']);

session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax',
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')]);
session_name('wfaadmin');
session_start();

if (empty($_SESSION['wfa_token'])) {
    $_SESSION['wfa_token'] = bin2hex(random_bytes(16));
}
$token = $_SESSION['wfa_token'];

function wfa_token_ok(): bool
{
    return isset($_POST['token'], $_SESSION['wfa_token'])
        && hash_equals((string) $_SESSION['wfa_token'], (string) $_POST['token']);
}

function h(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$meldung = '';
$fehler  = '';
$aktion  = $_POST['aktion'] ?? '';

/* ---------- Ersteinrichtung: Passwort festlegen ---------- */
if (!wfa_eingerichtet()) {
    if ($aktion === 'einrichten' && wfa_token_ok()) {
        $p1 = (string) ($_POST['passwort'] ?? '');
        $p2 = (string) ($_POST['passwort2'] ?? '');
        if (strlen($p1) < 8) {
            $fehler = 'Bitte mindestens 8 Zeichen wählen.';
        } elseif ($p1 !== $p2) {
            $fehler = 'Die beiden Eingaben stimmen nicht überein.';
        } else {
            $neu = ['passwort_hash' => password_hash($p1, PASSWORD_DEFAULT)];
            if ((string) $cfg['salt'] === '') {
                // nur beim allerersten Mal erzeugen — sonst wechseln die Besucherkennungen
                $neu['salt'] = bin2hex(random_bytes(16));
            }
            $ok = wfa_config_speichern($neu);
            if ($ok) {
                $_SESSION['wfa_admin'] = true;
                header('Location: zugriffe.php');
                exit;
            }
            $fehler = 'Die Einstellungsdatei konnte nicht geschrieben werden. '
                    . 'Bitte im Dateimanager für den Ordner wfa-log Schreibrechte setzen (755).';
        }
    }
    wfa_seite_anfang('Einrichtung');
    ?>
    <div class="karte schmal">
      <h1>Zugriffsprotokoll einrichten</h1>
      <p class="hinweis">Bitte einmalig ein Passwort für diese Auswertungsseite festlegen.
         Es hat nichts mit dem Archiv-Passwort zu tun und sollte ein anderes sein.</p>
      <?php if ($fehler): ?><p class="fehler"><?= h($fehler) ?></p><?php endif; ?>
      <form method="post" autocomplete="off">
        <input type="hidden" name="token" value="<?= h($token) ?>">
        <input type="hidden" name="aktion" value="einrichten">
        <label>Passwort<input type="password" name="passwort" required minlength="8" autofocus></label>
        <label>Passwort wiederholen<input type="password" name="passwort2" required minlength="8"></label>
        <button type="submit">Festlegen</button>
      </form>
    </div>
    <?php
    wfa_seite_ende();
    exit;
}

/* ---------- Abmelden ---------- */
if (isset($_GET['abmelden'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: zugriffe.php');
    exit;
}

/* ---------- Anmelden ---------- */
if (empty($_SESSION['wfa_admin'])) {
    if ($aktion === 'anmelden' && wfa_token_ok()) {
        $sperre = WFA_DIR . '/.versuche';
        $stand  = @json_decode((string) @file_get_contents($sperre), true) ?: ['n' => 0, 't' => 0];
        if ($stand['n'] >= 8 && (time() - $stand['t']) < 900) {
            $fehler = 'Zu viele Fehlversuche. Bitte 15 Minuten warten.';
        } elseif (password_verify((string) ($_POST['passwort'] ?? ''), (string) $cfg['passwort_hash'])) {
            @unlink($sperre);
            session_regenerate_id(true);
            $_SESSION['wfa_admin'] = true;
            $_SESSION['wfa_token'] = bin2hex(random_bytes(16));
            header('Location: zugriffe.php');
            exit;
        } else {
            usleep(600000);
            $neu = (time() - (int) $stand['t']) > 900 ? 1 : ((int) $stand['n'] + 1);
            @file_put_contents($sperre, json_encode(['n' => $neu, 't' => time()]), LOCK_EX);
            $fehler = 'Passwort falsch.';
        }
    }
    wfa_seite_anfang('Anmeldung');
    ?>
    <div class="karte schmal">
      <h1>Zugriffsprotokoll</h1>
      <p class="hinweis">Wessling Familienarchiv — Auswertung für den Verwalter.</p>
      <?php if ($fehler): ?><p class="fehler"><?= h($fehler) ?></p><?php endif; ?>
      <form method="post" autocomplete="off">
        <input type="hidden" name="token" value="<?= h($token) ?>">
        <input type="hidden" name="aktion" value="anmelden">
        <label>Passwort<input type="password" name="passwort" required autofocus></label>
        <button type="submit">Anmelden</button>
      </form>
    </div>
    <?php
    wfa_seite_ende();
    exit;
}

/* ---------- Einstellungen speichern ---------- */
if ($aktion === 'einstellungen' && wfa_token_ok()) {
    $neu = [
        'ip_speichern' => in_array($_POST['ip_speichern'] ?? '', ['gekuerzt', 'nein', 'voll'], true)
                          ? $_POST['ip_speichern'] : 'gekuerzt',
        'aufbewahrung' => max(0, min(120, (int) ($_POST['aufbewahrung'] ?? 24))),
    ];
    $p1 = (string) ($_POST['passwort_neu'] ?? '');
    if ($p1 !== '') {
        if (strlen($p1) < 8) {
            $fehler = 'Das neue Passwort braucht mindestens 8 Zeichen.';
        } else {
            $neu['passwort_hash'] = password_hash($p1, PASSWORD_DEFAULT);
        }
    }
    if ($fehler === '') {
        $meldung = wfa_config_speichern($neu) ? 'Einstellungen gespeichert.' : 'Speichern nicht möglich.';
        $cfg = wfa_config();
    }
}

/* ---------- Daten laden ---------- */
$monate = wfa_monate();
$monat  = (string) ($_GET['monat'] ?? ($monate[0] ?? date('Y-m')));
if (!preg_match('/^\d{4}-\d{2}$/', $monat)) {
    $monat = date('Y-m');
}
$bots_zeigen = isset($_GET['bots']);
$einzeln     = isset($_GET['einzeln']);

$eintraege = wfa_eintraege($monat);
if (!$bots_zeigen) {
    $eintraege = array_values(array_filter($eintraege, fn($e) => !$e['maschine']));
}
$besuche = wfa_besuche($eintraege);

/* ---------- CSV-Export ---------- */
if (isset($_GET['csv'])) {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="zugriffe-' . $monat . '.csv"');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");
    fputcsv($out, ['Beginn', 'Dauer (Min.)', 'Aufrufe', 'Land', 'Anbieter', 'Gerät',
                   'System', 'Browser', 'Sprache', 'IP', 'Besucherkennung', 'Automatisch'], ';');
    foreach ($besuche as $b) {
        fputcsv($out, [
            date('Y-m-d H:i:s', $b['beginn']), round(($b['ende'] - $b['beginn']) / 60, 1),
            $b['aufrufe'], $b['land'], $b['anbieter'], $b['geraet'], $b['system'],
            $b['browser'], $b['sprache'], $b['ip'], $b['kennung'], $b['maschine'] ? 'ja' : 'nein',
        ], ';');
    }
    fclose($out);
    exit;
}

$besucher = count(array_unique(array_column($besuche, 'kennung')));
$laender  = array_count_values(array_filter(array_column($besuche, 'land')));
arsort($laender);

wfa_seite_anfang('Zugriffe');
?>
<div class="kopf">
  <div>
    <h1>Zugriffe auf das Archiv</h1>
    <p class="hinweis">Wessling Familienarchiv · Auswertung für den Verwalter</p>
  </div>
  <a class="knopf leise" href="?abmelden=1">Abmelden</a>
</div>

<?php if ($meldung): ?><p class="meldung"><?= h($meldung) ?></p><?php endif; ?>
<?php if ($fehler): ?><p class="fehler"><?= h($fehler) ?></p><?php endif; ?>

<div class="leiste">
  <form method="get">
    <label>Monat
      <select name="monat" onchange="this.form.submit()">
        <?php foreach ($monate ?: [date('Y-m')] as $m): ?>
          <option value="<?= h($m) ?>"<?= $m === $monat ? ' selected' : '' ?>>
            <?= h(strftime_de($m)) ?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <label class="haken"><input type="checkbox" name="bots" value="1"
      onchange="this.form.submit()"<?= $bots_zeigen ? ' checked' : '' ?>> Maschinen mitzählen</label>
    <label class="haken"><input type="checkbox" name="einzeln" value="1"
      onchange="this.form.submit()"<?= $einzeln ? ' checked' : '' ?>> Einzelne Aufrufe statt Besuche</label>
    <a class="knopf leise" href="?monat=<?= h($monat) ?><?= $bots_zeigen ? '&bots=1' : '' ?>&csv=1">Als Tabelle laden</a>
  </form>
</div>

<div class="kacheln">
  <div class="kachel"><span class="zahl"><?= count($besuche) ?></span>Besuche</div>
  <div class="kachel"><span class="zahl"><?= $besucher ?></span>verschiedene Besucher</div>
  <div class="kachel"><span class="zahl"><?= count($laender) ?></span>Länder</div>
  <div class="kachel breit"><span class="zahl klein"><?= h(implode(' · ', array_slice(
      array_map(fn($l, $n) => "$l ($n)", array_keys($laender), $laender), 0, 4)) ?: '—') ?></span>Herkunft</div>
</div>

<?php if (!$besuche): ?>
  <p class="leer">Für diesen Monat liegen noch keine Einträge vor.</p>
<?php elseif ($einzeln): ?>
  <table>
    <thead><tr><th>Zeitpunkt</th><th>Land</th><th>Anbieter</th><th>Gerät</th>
      <th>Browser</th><th>Sprache</th><th>IP</th><th>Besucher</th></tr></thead>
    <tbody>
    <?php foreach (array_reverse($eintraege) as $e): ?>
      <tr<?= $e['maschine'] ? ' class="bot"' : '' ?>>
        <td class="nowrap"><?= h(date('d.m.Y H:i:s', $e['ts'])) ?></td>
        <td><?= h($e['land']) ?></td>
        <td class="anbieter"><?= h($e['anbieter'] ?: '—') ?></td>
        <td><?= h($e['geraet']) ?> · <?= h($e['system']) ?></td>
        <td><?= h($e['browser']) ?></td>
        <td><?= h($e['sprache'] ?: '—') ?></td>
        <td class="mono"><?= h($e['ip'] ?: '—') ?></td>
        <td class="mono"><?= h($e['kennung']) ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
<?php else: ?>
  <table>
    <thead><tr><th>Beginn</th><th>Dauer</th><th>Aufrufe</th><th>Land</th><th>Anbieter</th>
      <th>Gerät</th><th>Sprache</th><th>IP</th><th>Besucher</th></tr></thead>
    <tbody>
    <?php foreach ($besuche as $b): ?>
      <tr<?= $b['maschine'] ? ' class="bot"' : '' ?>>
        <td class="nowrap"><?= h(date('d.m.Y H:i', $b['beginn'])) ?></td>
        <td class="nowrap"><?= h($b['ende'] > $b['beginn'] ? wfa_dauer($b['ende'] - $b['beginn']) : '—') ?></td>
        <td><?= (int) $b['aufrufe'] ?></td>
        <td><?= h($b['land']) ?></td>
        <td class="anbieter"><?= h($b['anbieter'] ?: '—') ?></td>
        <td><?= h($b['geraet']) ?> · <?= h($b['system']) ?></td>
        <td><?= h($b['sprache'] ?: '—') ?></td>
        <td class="mono"><?= h($b['ip'] ?: '—') ?></td>
        <td class="mono"><?= h($b['kennung']) ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <p class="fussnote">„Besucher" ist eine anonyme Kennung aus Adresse und Browser — gleiche Kennung heißt
     mit hoher Wahrscheinlichkeit dieselbe Person. Aufrufe desselben Besuchers innerhalb einer halben Stunde
     gelten als ein Besuch; die Dauer ist der Abstand vom ersten zum letzten Seitenaufruf.<br>
     Zugriffe aus Rechenzentren, von Hostern und über VPN-Ausgänge (Amazon, Google, OVH, Scaleway, M247 …)
     sind <strong>keine Menschen</strong>, sondern Suchprogramme, die das ganze Internet abklappern. Sie werden
     hier standardmäßig ausgeblendet — über „Maschinen mitzählen" lassen sie sich grau einblenden.
     Echte Familienbesuche kommen über Anbieter wie Telekom, Vodafone, Orange oder Vectra.</p>
<?php endif; ?>

<details class="einstellungen">
  <summary>Einstellungen</summary>
  <form method="post">
    <input type="hidden" name="token" value="<?= h($token) ?>">
    <input type="hidden" name="aktion" value="einstellungen">
    <label>IP-Adressen speichern
      <select name="ip_speichern">
        <option value="gekuerzt"<?= $cfg['ip_speichern'] === 'gekuerzt' ? ' selected' : '' ?>>gekürzt (empfohlen)</option>
        <option value="nein"<?= $cfg['ip_speichern'] === 'nein' ? ' selected' : '' ?>>gar nicht</option>
        <option value="voll"<?= $cfg['ip_speichern'] === 'voll' ? ' selected' : '' ?>>vollständig</option>
      </select>
    </label>
    <label>Einträge aufbewahren (Monate, 0 = unbegrenzt)
      <input type="number" name="aufbewahrung" min="0" max="120" value="<?= (int) $cfg['aufbewahrung'] ?>">
    </label>
    <label>Neues Passwort (leer lassen = unverändert)
      <input type="password" name="passwort_neu" autocomplete="new-password">
    </label>
    <button type="submit">Speichern</button>
  </form>
</details>

<p class="quelle">Zuordnung von Land und Anbieter offline anhand der Datenbanken von
  <a href="https://www.nro.net/">NRO</a>, <a href="https://www.routeviews.org/">RouteViews</a> und
  <a href="https://db-ip.com/">DB-IP</a> (CC BY 4.0). Es werden keine Daten an Dritte übermittelt.</p>

<?php
wfa_seite_ende();

/* ------------------------------------------------------------------ */

function strftime_de(string $monat): string
{
    static $namen = [1 => 'Januar', 'Februar', 'März', 'April', 'Mai', 'Juni', 'Juli',
                     'August', 'September', 'Oktober', 'November', 'Dezember'];
    [$j, $m] = array_map('intval', explode('-', $monat));
    return ($namen[$m] ?? $monat) . ' ' . $j;
}

function wfa_seite_anfang(string $titel): void
{
    header('Content-Type: text/html; charset=utf-8');
    header('X-Robots-Tag: noindex, nofollow');
    ?><!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= htmlspecialchars($titel) ?> · Wessling Familienarchiv</title>
<style>
  :root { --tinte:#20242b; --grau:#6b7280; --linie:#e3e0d8; --papier:#faf8f4;
          --akzent:#7a2e2e; --flaeche:#fff; }
  * { box-sizing:border-box; }
  body { margin:0; padding:2rem 1.25rem 4rem; background:var(--papier); color:var(--tinte);
         font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .kopf, .karte, .leiste, .kacheln, table, .fussnote, .einstellungen, .quelle, .meldung,
  .fehler, .leer { max-width:1080px; margin-left:auto; margin-right:auto; }
  h1 { font:600 1.6rem/1.2 Georgia,"Times New Roman",serif; margin:0 0 .25rem; }
  .kopf { display:flex; align-items:flex-start; justify-content:space-between; gap:1rem; margin-bottom:1.5rem; }
  .hinweis { color:var(--grau); margin:.25rem 0 0; font-size:.92rem; }
  .karte { background:var(--flaeche); border:1px solid var(--linie); border-radius:10px; padding:1.75rem; }
  .schmal { max-width:26rem; margin-top:8vh; }
  label { display:block; margin:1rem 0 0; font-size:.9rem; color:var(--grau); }
  input, select { display:block; width:100%; margin-top:.35rem; padding:.55rem .7rem; font-size:1rem;
         border:1px solid var(--linie); border-radius:7px; background:#fff; color:var(--tinte); }
  button { margin-top:1.25rem; padding:.6rem 1.4rem; font-size:1rem; border:0; border-radius:7px;
         background:var(--akzent); color:#fff; cursor:pointer; }
  button:hover { background:#8f3838; }
  .knopf { display:inline-block; padding:.45rem 1rem; border:1px solid var(--linie); border-radius:7px;
         background:#fff; color:var(--tinte); text-decoration:none; font-size:.88rem; white-space:nowrap; }
  .knopf:hover { border-color:var(--grau); }
  .leiste form { display:flex; flex-wrap:wrap; gap:1rem 1.5rem; align-items:center;
         background:var(--flaeche); border:1px solid var(--linie); border-radius:10px; padding:.9rem 1.1rem; }
  .leiste label { margin:0; display:flex; align-items:center; gap:.5rem; }
  .leiste select { width:auto; margin:0; }
  .haken input { width:auto; margin:0; }
  .kacheln { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:.9rem; margin:1.25rem auto; }
  .kachel { background:var(--flaeche); border:1px solid var(--linie); border-radius:10px;
         padding:1rem 1.1rem; font-size:.85rem; color:var(--grau); }
  .kachel .zahl { display:block; font:600 1.9rem/1.15 Georgia,serif; color:var(--tinte); }
  .kachel .zahl.klein { font-size:1rem; line-height:1.35; padding-top:.35rem; }
  .breit { grid-column:span 2; }
  table { width:100%; border-collapse:collapse; background:var(--flaeche);
         border:1px solid var(--linie); border-radius:10px; overflow:hidden; font-size:.9rem; }
  th { text-align:left; font-weight:600; font-size:.78rem; text-transform:uppercase;
       letter-spacing:.04em; color:var(--grau); padding:.7rem .8rem; border-bottom:1px solid var(--linie); }
  td { padding:.6rem .8rem; border-bottom:1px solid #f1efe9; vertical-align:top; }
  tr:last-child td { border-bottom:0; }
  tr:hover td { background:#fcfbf8; }
  tr.bot td { color:#9aa0a6; font-style:italic; }
  .mono { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.85em; color:var(--grau); }
  .nowrap { white-space:nowrap; }
  .anbieter { max-width:16rem; }
  .fussnote, .quelle { color:var(--grau); font-size:.82rem; margin-top:1rem; }
  .quelle a { color:var(--grau); }
  .fehler { background:#fdf2f2; border:1px solid #f3d0d0; color:#8f2f2f;
            padding:.7rem .9rem; border-radius:7px; margin:1rem auto; font-size:.9rem; }
  .meldung { background:#f2f8f2; border:1px solid #cfe3cf; color:#2f6b34;
            padding:.7rem .9rem; border-radius:7px; margin:1rem auto; font-size:.9rem; }
  .leer { color:var(--grau); padding:2.5rem 0; text-align:center; }
  .einstellungen { margin-top:2.5rem; background:var(--flaeche); border:1px solid var(--linie);
            border-radius:10px; padding:.9rem 1.1rem; }
  .einstellungen summary { cursor:pointer; font-size:.9rem; color:var(--grau); }
  .einstellungen form { max-width:24rem; }
  @media (max-width:640px) { table { font-size:.8rem; } .breit { grid-column:span 1; } }
</style>
</head><body><?php
}

function wfa_seite_ende(): void
{
    echo "</body></html>\n";
}
