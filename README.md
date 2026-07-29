# archive-build — Baukasten des Wessling-Familienarchivs (MASTER)

Dieser Ordner ist die **Master-Ablage** des Archivs. Jede Arbeitssitzung mit Claude
arbeitet direkt auf diesen Dateien; die Website wird daraus gebaut.

## Dateien

| Datei | Zweck |
|---|---|
| `data.json` | Der gesamte Inhalt: Personen (321), Quellen, Ereignisse, Erzählungen, Fotos, Stammbaum-Relationen. **Hier wird redigiert.** |
| `engine.html` | Die familienneutrale App (Oberfläche, Stammbaum, Suche, „Fragen"-Reiter). Enthält den Marker `/*__DATA__*/`. |
| `gate_template.html` | Passwort-Schleuse (Vorlage) mit Marker `__B64__`. |
| `config.json` | Archiv-Passwort und Einstellungen. |
| `build.py` | Baut das Archiv: `python3 build.py --encrypt` → `index.html` für den Webserver. |
| `index.html` | Das fertige, verschlüsselte Archiv (wird bei jedem Build überschrieben). |

## Redaktions-Rundlauf

1. Neue Quellen landen in `../Content` (Eingangskorb, auch für die Familie).
2. Claude transkribiert/übersetzt, pflegt `data.json`, baut `index.html`.
3. Veröffentlichung: Push ins private GitHub-Repo `wessling-archiv` — Branch `main` = dieser Baukasten, Branch `live` = nur `index.html`. Hostinger deployt `live` automatisch (Webhook).

## Sicherheit

- `data.json` und `archiv_klar.html` sind **unverschlüsselt** → niemals auf den Webserver laden. Öffentlich ist nur die AES-verschlüsselte `index.html`.
- Verschlüsselung: PBKDF2-SHA256 (250.000 Iterationen) + AES-256-GCM; Passwort in `config.json`.
- Deploy-Token (`../deploy-token.txt`): nur Zugriff auf das eine Repo, jederzeit bei GitHub widerrufbar.
