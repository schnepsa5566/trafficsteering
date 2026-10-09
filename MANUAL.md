# trafficSteering – Benutzerhandbuch

`trafficSteering.py` gleicht die **Internal Domains** von Cisco Secure Access
(*Internet Security → Traffic Steering → Bypass Secure Access*) mit der Datei
`trafficUrls.txt` ab.

`trafficUrls.txt` ist der **vollständige Soll-Zustand**:

- Domains, die in der Datei stehen, aber bei Cisco fehlen, werden **angelegt**.
- Domains, die bei Cisco existieren, aber nicht in der Datei stehen, werden
  **gelöscht** – auch manuell im Portal angelegte.
- Bestehende Einträge mit abweichenden Einstellungen werden **angepasst**.
- Doppelte Einträge derselben Domain bei Cisco werden bis auf einen gelöscht.

Der Abgleich ist idempotent: Stimmt der Ist-Zustand bereits, wird nichts
geschrieben.

---

## 1. Voraussetzungen

- Python 3.10 oder neuer
- Python-Pakete `requests` und `truststore`:

  ```
  pip install requests truststore
  ```

  `truststore` sorgt dafür, dass TLS-Zertifikate gegen den
  Windows-Zertifikatsspeicher geprüft werden. Das ist hinter einem Proxy mit
  TLS-Inspection nötig, sonst kommt `CERTIFICATE_VERIFY_FAILED`.

- Ein API-Key für Cisco Secure Access mit den Scopes
  - `deployments.internaldomains:read`
  - `deployments.internaldomains:write`

  (Für `--dry-run` und `--check` genügt `:read`.)

---

## 2. Credentials einrichten

Die Credentials werden in folgender Reihenfolge gesucht – Umgebungsvariablen
haben Vorrang:

1. Umgebungsvariablen `CISCO_SECURE_ACCESS_KEY` und `CISCO_SECURE_ACCESS_SECRET`
2. Datei `secrets.env` neben dem Script (oder die mit `--secrets-file`
   angegebene Datei)

### secrets.env anlegen

`secrets.env.example` nach `secrets.env` kopieren und Werte eintragen:

```
CISCO_SECURE_ACCESS_KEY=<api-key>
CISCO_SECURE_ACCESS_SECRET=<api-secret>
```

Format: `KEY=VALUE`, eine Zeile pro Wert. Leerzeilen und `#`-Kommentare sind
erlaubt, Werte dürfen in `"…"` oder `'…'` stehen.

> **Wichtig:** `secrets.env` und alle `*.secrets.env` enthalten Zugangsdaten und
> dürfen **nicht** ins Git eingecheckt werden.

### Mehrere Organisationen / Umgebungen

Für jede Organisation eine eigene Datei anlegen (z. B. `test.secrets.env`,
`svd.secrets.env`) und beim Aufruf angeben:

```
python trafficSteering.py --secrets-file svd.secrets.env --dry-run
```

Eine explizit angegebene Datei muss existieren, sonst bricht das Script ab.

### Variante: Umgebungsvariablen (PowerShell)

```powershell
$env:CISCO_SECURE_ACCESS_KEY    = "<api-key>"
$env:CISCO_SECURE_ACCESS_SECRET = "<api-secret>"
python trafficSteering.py --dry-run
```

---

## 3. Die Datei trafficUrls.txt

- Eine Domain pro Zeile.
- Leerzeilen werden ignoriert; alles ab `#` ist Kommentar (auch am Zeilenende).
- Groß-/Kleinschreibung spielt keine Rolle, ein abschließender Punkt wird
  entfernt.
- Subdomains sind implizit enthalten: `*.example.com` ist gleichbedeutend mit
  `example.com`.
- Doppelte Zeilen sind erlaubt und werden beim Einlesen zusammengefasst.

Beispiel:

```
# BMC Helix
sv-dwp.onbmc.com
sv-is.onbmc.com          # Integration Service
*.example.com            # = example.com inkl. Subdomains
```

Eine andere Datei kann mit `--file` angegeben werden.

### Schutz vor versehentlichem Löschen

Enthält die Datei keine einzige Domain, bricht das Script ab, weil sonst alle
Internal Domains gelöscht würden. Wer das wirklich will, muss `--allow-empty`
angeben.

---

## 4. Empfohlener Ablauf

1. **Vorschau** – zeigt für jede Domain der Datei, ob sie bei Cisco existiert,
   und was geändert würde. Es wird nichts geschrieben.

   ```
   python trafficSteering.py --dry-run
   ```

2. **Abgleich ausführen** – zeigt die Änderungen und fragt vor dem Schreiben
   nach (`y`/`yes`/`j`/`ja` bestätigt, alles andere bricht ab).

   ```
   python trafficSteering.py
   ```

3. **Automatisiert** (z. B. Pipeline/Scheduler) – ohne Rückfrage:

   ```
   python trafficSteering.py --yes
   ```

---

## 5. Parameter

| Parameter               | Bedeutung                                                                                       |
|-------------------------|-------------------------------------------------------------------------------------------------|
| `--dry-run`             | Nur Unterschiede anzeigen, nichts ändern                                                        |
| `-y`, `--yes`           | Änderungen ohne Rückfrage durchführen                                                           |
| `--file DATEI`          | Datei mit dem Soll-Zustand (Default: `trafficUrls.txt` neben dem Script)                        |
| `--secrets-file DATEI`  | Datei mit den Credentials (Default: `secrets.env` neben dem Script)                             |
| `--allow-empty`         | Leere Soll-Liste erlauben – **löscht alle Internal Domains**                                    |
| `--check DOMAIN`        | Nur prüfen, ob `DOMAIN` bei Cisco existiert (offizielle API und Portal-Liste), nichts ändern     |
| `--org-id ID`           | Organisations-ID für die Portal-Liste bei `--check` (Default: `8421138`)                        |
| `--debug`               | Rohdaten der Cisco-Antwort ausgeben (Fehlersuche)                                               |
| `--no-color`            | Ausgabe ohne Farben (ebenso über Umgebungsvariable `NO_COLOR`)                                  |
| `-h`, `--help`          | Hilfe anzeigen                                                                                  |

---

## 6. Ausgabe lesen

### Normaler Lauf

```
Vorhanden: 24, Soll: 25

Unverändert: 22
  + sv-new.onbmc.com
  - old.example.com
  ~ sv-is.onbmc.com (includeAllVAs=False)

Hinzufügen: 1  Löschen: 1  Anpassen: 1
```

| Zeichen | Farbe | Bedeutung                                              |
|---------|-------|--------------------------------------------------------|
| `+`     | grün  | fehlt bei Cisco → wird angelegt                        |
| `-`     | rot   | nur bei Cisco bzw. doppelt vorhanden → wird gelöscht   |
| `~`     | gelb  | existiert, Einstellungen weichen ab → wird angepasst   |
| `=`     | grau  | existiert und passt (nur bei `--dry-run` aufgelistet)  |

### Was beim Schreiben passiert

1. Nach der Bestätigung wird der Stand bei Cisco **erneut geladen**. Hat sich
   seit der Vorschau etwas geändert, werden die neuen Änderungen angezeigt und
   (ohne `--yes`) nochmals bestätigt.
2. Reihenfolge: löschen → anpassen → anlegen.
3. Danach wird das Ergebnis geprüft. Meldet Cisco einen abweichenden Zustand,
   gibt das Script eine Warnung aus und endet mit Exit-Code `1`.

### Exit-Codes

| Code | Bedeutung                                                      |
|------|----------------------------------------------------------------|
| `0`  | Erfolgreich, keine Änderung nötig, Dry-Run oder abgebrochen    |
| `1`  | Fehler (Credentials, API-Fehler, Abweichung nach dem Abgleich) |

---

## 7. Einstellungen der Einträge

Jede Internal Domain wird mit folgenden Einstellungen angelegt bzw. darauf
angepasst („All Devices“):

- `includeAllVAs = true`
- `includeAllMobileDevices = true`
- keine Einschränkung auf Sites (gilt für alle Sites)

Eine vorhandene Beschreibung (`description`) bleibt beim Anpassen erhalten.
Die Site-Zuordnung wird beim Vergleich bewusst nicht geprüft.

---

## 8. Einschränkungen

### „Bypass web proxy only“-Einträge sind unsichtbar

Die offizielle API (`/deployments/v2/internaldomains`) liefert nur Einträge vom
Typ **Bypass Secure Access**. Einträge vom Typ **Bypass web proxy only** sieht
das Script nicht. Folgen:

- Eine Domain, die im Portal als „web proxy only“ existiert, wird als
  **fehlt** (`+`) angezeigt.
- Solche Einträge werden vom Script weder gelöscht noch umgestellt.
- Abhilfe: den Eintrag im Portal auf „Bypass Secure Access“ umstellen – danach
  erkennt das Script ihn als vorhanden.

Das Portal zeigt deshalb ggf. mehr Einträge als das Script.

---

## 9. Fehlersuche

### Domain wird als „fehlt“ angezeigt, ist im Portal aber sichtbar

```
python trafficSteering.py --check sv-is.onbmc.com
```

Prüft nur lesend:

1. die offizielle API – exakter Treffer und ähnliche Einträge,
2. die (undokumentierte) Portal-Liste, inkl. `domainType`.

Ist die Domain nur in der Portal-Liste zu finden, handelt es sich meist um
einen „web proxy only“-Eintrag (siehe Abschnitt 8). Liefert die Portal-Liste
einen HTTP-Fehler, ist sie mit dem API-Key nicht abrufbar – Punkt 1 ist davon
nicht betroffen.

Für eine andere Organisation `--org-id` mitgeben.

### Rohdaten ansehen

```
python trafficSteering.py --dry-run --debug
```

Zeigt alle von Cisco gelieferten Einträge mit ID sowie für jede als fehlend
erkannte Domain ähnliche Einträge bei Cisco.

### Häufige Fehlermeldungen

| Meldung                                                       | Ursache / Lösung                                                                 |
|---------------------------------------------------------------|----------------------------------------------------------------------------------|
| `CISCO_SECURE_ACCESS_KEY und … müssen gesetzt sein`           | Credentials fehlen – `secrets.env` anlegen oder Umgebungsvariablen setzen         |
| `Secrets-Datei … nicht gefunden`                              | Pfad bei `--secrets-file` prüfen                                                  |
| `… enthält keine Einträge`                                    | Soll-Datei leer – Datei prüfen, oder bewusst `--allow-empty` verwenden           |
| `HTTP 401` beim Token                                         | API-Key/Secret falsch oder abgelaufen                                             |
| `HTTP 403`                                                    | API-Key fehlt der Scope `deployments.internaldomains:read` bzw. `:write`          |
| `… liefert auf Seite N dieselben Einträge wie zuvor`          | API ignoriert die Pagination – Abbruch ohne Änderungen, später erneut versuchen  |
| `HTTP 429 - warte …s`                                         | Rate Limit (Cisco: 14/min, 350/30 min pro Key) – das Script wartet 60, 120, 240, dann je 300 s und wiederholt, insgesamt bis zu 30 min |

---

## 10. urlCheck.py – Erreichbarkeit, Block Page und Kategorien

`urlCheck.py` ruft jede Adresse aus `urlList.txt` auf und prüft, ob echter
Content oder eine Seite von Cisco Secure Access zurückkommt. Ergebnis ist ein
HTML-Report. Zusätzlich werden je FQDN über die Cisco API abgefragt und als
CSV (`fqdn,kategorie,action,regel,letzter_zugriff`) ausgegeben:

- die Kategorie über die **Investigate API**,
- ob Cisco die Domain zulässt oder blockt, aus dem **Cisco-Log** (Reports API,
  Activity Search): das zuletzt protokollierte Verdict samt Regel.

Das Script nutzt dieselben Credentials-Mechanismen wie `trafficSteering.py`
(`secrets.env`, `--secrets-file`, Umgebungsvariablen). Der API-Key braucht die
Scopes `investigate.investigate:read` (Kategorie) und
`reports.granularEvents:read` (Action). Fehlt ein Scope oder ist die API nicht
erreichbar, steht in der betroffenen Spalte `nicht verfügbar` bzw.
`Fehler: …`; Report und CSV werden trotzdem erstellt.

> Die Secrets-Datei muss zur Organisation gehören, über die die Clients
> surfen – sonst findet die Reports API keine Zugriffe (`keine Daten`).

### Die Datei urlList.txt

- Eine Adresse pro Zeile: FQDN (`www.example.com`), IP-Adresse (IPv4/IPv6)
  oder vollständige URL (`https://host/pfad`). Auch `host/pfad` ist erlaubt.
- Leerzeilen und `#`-Kommentare werden ignoriert, Duplikate entfernt.
- Ohne Schema wird zuerst `https://`, bei Fehler `http://` aufgerufen.

### Aufruf

```
python urlCheck.py                         # Seitenaufrufe + Report + CSV
python urlCheck.py --no-categories         # nur Seitenaufrufe + Report, keine API
python urlCheck.py --categories-only       # nur API-Abfragen + CSV, keine Seitenaufrufe
python urlCheck.py --categories-only --hours 168   # Cisco-Log der letzten 7 Tage
python urlCheck.py --file andere.txt --secrets-file svd.secrets.env
python urlCheck.py --resume                # abgebrochenen Lauf fortsetzen
```

Report und CSV landen in `reports/` (nicht im Git):

- `reports/urlCheck_JJJJMMTT_HHMMSS.html`
- `reports/categories_JJJJMMTT_HHMMSS.csv` – Trenner `,`, UTF-8 mit BOM
  (Excel), mehrere Kategorien je Domain mit `; ` getrennt.

### Mitschrift und Fortsetzen (--resume)

Jedes Zwischenergebnis wird sofort in eine Mitschrift geschrieben:
Seitenaufrufe, Kategorien und Cisco-Log-Einträge.

- Datei: `reports/journal/urlCheck_<hash>.jsonl`. `<hash>` sind die ersten
  16 Zeichen des SHA-256 des **Inhalts** der Quelldatei. Jede Adressliste
  hat damit ihre eigene Mitschrift, und Läufe mit verschiedenen Listen
  können parallel laufen. Zwei gleichzeitige Läufe mit **derselben** Liste
  schreiben allerdings in dieselbe Datei und sollten vermieden werden.
- `--resume` liest die Mitschrift ein, übernimmt die vorhandenen Ergebnisse
  und fragt nur noch Fehlendes ab.
- Wurde die Quelldatei geändert, passt der Hash nicht mehr. Der Lauf
  beginnt dann von vorne. Die alte Mitschrift bleibt liegen und kann
  gelöscht werden.
- Ohne `--resume` wird eine vorhandene Mitschrift derselben Liste
  überschrieben.
- API-Abfragen mit Fehler (z. B. `HTTP 429` nach 30 Minuten Wartezeit,
  API nicht erreichbar) werden nicht mitgeschrieben. Ein Lauf mit
  `--resume` fragt genau diese Einträge erneut ab.
- Nach einem vollständigen Lauf ohne API-Fehler wird die Mitschrift
  gelöscht.
- Ergebnisse aus der Mitschrift werden unverändert übernommen. Das gilt
  auch für die Cisco-Log-Werte; sie entsprechen also dem Zeitpunkt der
  ursprünglichen Abfrage.

### Action aus dem Cisco-Log

Cisco Secure Access hat kein API-Endpoint, das eine Policy für eine Domain
„testet“. Die Spalte `action` stammt deshalb aus dem Activity-Log
(`GET /reports/v2/activity?domains=<fqdn>`): Gesucht wird im Zeitraum
`--hours` (Default 24 h), je Typ (DNS, Proxy, Firewall …) zählt das jüngste
Event. Ist eines davon `blocked`, gilt die Domain als geblockt.

| action            | Bedeutung                                                     |
|-------------------|---------------------------------------------------------------|
| `zugelassen`      | letzter protokollierter Zugriff wurde erlaubt                 |
| `geblockt`        | letzter protokollierter Zugriff wurde blockiert               |
| `keine Daten`     | kein Zugriff auf die Domain im Zeitraum protokolliert         |
| `keine Daten (IP)`| IP-Adressen werden nicht abgefragt                            |
| `nicht verfügbar` | Scope `reports.granularEvents:read` fehlt bzw. keine Credentials |
| `Fehler: …`       | API nicht erreichbar                                          |

`regel` enthält Name und/oder ID der auslösenden Regel (z. B.
`Webfilter_SVS (ID 2838182)`), `letzter_zugriff` den Zeitpunkt des Events.

Grenzen:

- Es gibt nur ein Ergebnis, wenn die Domain im Zeitraum tatsächlich
  aufgerufen wurde – von irgendeinem Client der Organisation.
- Neue Zugriffe erscheinen erst nach einigen Minuten im Log. Die
  Seitenaufrufe eines normalen Laufs sind daher meist noch nicht enthalten;
  für aktuelle Werte später `--categories-only` laufen lassen.
- Das Ergebnis des direkten Seitenaufrufs (Spalte *Ergebnis* im HTML-Report)
  und das Cisco-Log (Spalte *Cisco-Log*) stehen im Report nebeneinander.

### Parameter

| Parameter               | Bedeutung                                                                      |
|-------------------------|--------------------------------------------------------------------------------|
| `--file DATEI`          | Adressliste (Default: `urlList.txt` neben dem Script)                          |
| `--out-dir DIR`         | Zielverzeichnis für Report und CSV (Default: `reports/`)                       |
| `--secrets-file DATEI`  | Credentials für die Cisco API (Default: `secrets.env`)                         |
| `--no-categories`       | Keine API-Abfragen (Kategorie, Cisco-Log) und keine CSV                        |
| `--categories-only`     | Nur API-Abfragen und CSV – keine Seitenaufrufe, kein HTML-Report               |
| `--hours N`             | Zeitraum für die Suche im Cisco-Log in Stunden (Default: 24)                   |
| `--workers N`           | Parallele Seitenaufrufe (Default: 10)                                          |
| `--timeout SEK`         | Timeout je Seitenaufruf (Default: 15)                                          |
| `--proxy URL`           | Expliziter Proxy (Default: `HTTP_PROXY`/`HTTPS_PROXY` aus der Umgebung)        |
| `--insecure`            | TLS-Zertifikate gar nicht prüfen (Spalte *Zertifikat*: `nicht geprüft`)        |
| `--marker TEXT`         | Zusätzlicher Text, der eine Seite als Block Page kennzeichnet (mehrfach)       |
| `--save-bodies`         | Empfangene Seiten unter `<out-dir>/bodies/` speichern (zum Anpassen der Marker)|
| `--resume`              | Abgebrochenen Lauf aus der Mitschrift fortsetzen (siehe oben)                  |
| `--no-color`            | Ausgabe ohne Farben                                                            |

### Ergebnisse

| Ergebnis    | Bedeutung                                                                                       |
|-------------|-------------------------------------------------------------------------------------------------|
| `OK`        | Content des Zielservers erreicht (auch 4xx/5xx des Zielservers)                                 |
| `BLOCKIERT` | Cisco Block Page: Weiterleitung auf `*.block.sse.cisco.com`, Block-Page-Merkmale im Inhalt oder DNS-Antwort im Block-Netz `146.112.61.0/24` |
| `WARNUNG`   | Block Page mit Block Type `warn`                                                                |
| `FEHLER`    | Nicht erreicht: DNS-Fehler, Timeout, TLS-Fehler oder Fehlerseite des Proxys (z. B. `515 Upstream Certificate Untrusted`) |

**Zertifikatsfehler** brechen den Aufruf nicht ab: Das Script prüft das
Zertifikat zuerst, wiederholt den Aufruf bei einem Fehler ohne Prüfung und
bewertet den Inhalt trotzdem. Die Spalte *Zertifikat* im Report zeigt
`gültig`, `ungültig: <Grund>` oder (mit `--insecure`) `nicht geprüft`; bei
reinem HTTP bleibt sie leer.

Bei Block Pages übernimmt der Report aus der *Diagnostic Info* den Block Type
und die auslösende Regel (Name und ID). Im HTML-Report lässt sich durch Klick
auf die Zähler nach Ergebnis filtern und durch Klick auf eine Spaltenüberschrift
sortieren.

Die Erkennungsmerkmale stehen als Konstanten oben im Script
(`BLOCK_HOST_MARKERS`, `BLOCK_BODY_MARKERS`, `BLOCK_NETWORKS`,
`PROXY_ERROR_MARKERS`, `WARN_BLOCK_TYPES`). Bei einer angepassten Block Page
eine blockierte Adresse mit `--save-bodies` aufrufen und ein eindeutiges
Merkmal per `--marker` mitgeben oder in die Konstanten aufnehmen.

### Einschränkungen

- Das Script prüft aus Sicht des Rechners, auf dem es läuft. Der Traffic muss
  dort durch Secure Access laufen (Secure Client oder Proxy). Eine PAC-Datei
  wertet Python nicht aus – ggf. `--proxy` angeben.
- IP-Adressen werden nicht kategorisiert (Investigate arbeitet mit Domains);
  in der CSV steht `IP - keine Kategorisierung`.
- Die Kategorie kommt aus der globalen Cisco-Datenbank. Ob eine Seite
  blockiert wird, entscheidet die eigene Policy – z. B. ist
  `internetbadguys.com` als *Phishing* kategorisiert, wird aber nur
  blockiert, wenn die Policy das vorsieht.
