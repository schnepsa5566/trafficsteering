#!/usr/bin/env python3
"""
Gleicht die Internal Domains (Traffic Steering -> Bypass Secure Access)
von Cisco Secure Access mit dem Inhalt von trafficUrls.txt ab.

- trafficUrls.txt ist der vollständige Soll-Zustand: nicht aufgeführte
  Internal Domains werden gelöscht, neue angelegt, abweichende angepasst.
- Idempotent: stimmt der Ist-Zustand bereits, wird nichts geschrieben.
- Credentials kommen aus Umgebungsvariablen oder aus secrets.env
  (andere Datei per --secrets-file).

API: https://api.sse.cisco.com/deployments/v2/internaldomains
Scopes: deployments.internaldomains:read / :write
"""

import os
import sys
import json
import time
import argparse
import warnings

# requests warnt bei chardet >= 6 (von reportlab installiert) - harmlos
warnings.filterwarnings("ignore", message=".*doesn't match a supported version.*")
import requests

# TLS-Zertifikate gegen den Betriebssystem-Speicher (Windows-Zertifikatsspeicher)
# prüfen statt gegen certifi - nötig hinter TLS-Inspection (Firmen-Root-CA).
try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    print("Hinweis: 'truststore' nicht installiert - verwende certifi-Bundle "
          "(pip install truststore)", file=sys.stderr)


BASE_URL = "https://api.sse.cisco.com"
TOKEN_URL = f"{BASE_URL}/auth/v2/token"
INTERNAL_DOMAINS_URL = f"{BASE_URL}/deployments/v2/internaldomains"

# Undokumentierte Liste, die das Portal (GUI) verwendet - nur für --check,
# ausschließlich lesend.
PORTAL_DOMAINS_URL = (
    "https://api.umbrella.com/sse/internal/v3/organizations/"
    "{org_id}/internaldomains"
)
ORG_ID = 8421138

# ------------------------------------------------------------------
# Konfiguration
# ------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_FILE = os.path.join(SCRIPT_DIR, "secrets.env")
DEFAULT_URLS_FILE = os.path.join(SCRIPT_DIR, "trafficUrls.txt")

# Gewünschte Einstellungen je Internal Domain ("All Devices").
# Neue Einträge werden ohne siteIds angelegt und gelten damit für alle Sites.
DESIRED_SETTINGS = {
    "includeAllVAs": True,
    "includeAllMobileDevices": True,
}

PAGE_LIMIT = 100

# Wiederholungen bei Rate Limit (429) bzw. kurzzeitiger Überlastung
RETRY_STATUS = (429, 502, 503, 504)
MAX_RETRIES = 6
MAX_RETRY_DELAY = 60

# Rate Limits laut Cisco (Deployments/Admin, pro API-Key):
# 5/Sekunde, 14/Minute, 350/30 Minuten. Ein Retry-After-Header ist nicht
# dokumentiert. Bei 429 daher mindestens eine Minute warten (Minutenfenster
# läuft ab), dann steigend bis RATE_LIMIT_MAX_DELAY, insgesamt so lange,
# dass auch das 30-Minuten-Fenster sicher abgelaufen ist.
RATE_LIMIT_DELAY = 60
RATE_LIMIT_MAX_DELAY = 300
RATE_LIMIT_MAX_WAIT = 30 * 60

# ------------------------------------------------------------------
# Farbige Ausgabe
# ------------------------------------------------------------------

GREEN = "32"
RED = "31"
YELLOW = "33"
GREY = "90"

USE_COLOR = False
DEBUG = False


def setup_color(disabled):
    """ANSI-Farben aktivieren, sofern sinnvoll."""

    global USE_COLOR

    USE_COLOR = (
        not disabled
        and "NO_COLOR" not in os.environ
        and sys.stdout.isatty()
    )

    if USE_COLOR and os.name == "nt":
        # Aktiviert die VT-Verarbeitung der Windows-Konsole
        os.system("")


def color(text, code):
    if not USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


# ------------------------------------------------------------------
# Eingaben
# ------------------------------------------------------------------

def load_secrets(path):
    """
    secrets.env (KEY=VALUE) einlesen. Umgebungsvariablen haben Vorrang.
    """

    secrets = {}

    if os.path.isfile(path):
        with open(path, encoding="utf-8-sig") as handle:
            for line in handle:
                line = line.strip()

                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                value = value.strip()

                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]

                secrets[key.strip()] = value

    for key in ("CISCO_SECURE_ACCESS_KEY", "CISCO_SECURE_ACCESS_SECRET"):
        if os.environ.get(key):
            secrets[key] = os.environ[key]

    return secrets


def normalize_address(address):
    """
    Einträge vergleichbar machen: FQDNs sind case-insensitiv,
    Internal Domains haben ein implizites Wildcard (*.x.com == x.com).
    """

    address = address.strip().lower().rstrip(".")

    if address.startswith("*."):
        address = address[2:]

    return address


def load_desired_addresses(path):
    """
    Soll-Zustand aus trafficUrls.txt lesen.
    Leerzeilen und #-Kommentare werden ignoriert, Duplikate entfernt.
    """

    addresses = []
    seen = set()

    with open(path, encoding="utf-8-sig") as handle:
        for line in handle:
            entry = line.split("#", 1)[0].strip()

            if not entry:
                continue

            entry = normalize_address(entry)

            if entry not in seen:
                seen.add(entry)
                addresses.append(entry)

    return addresses


def compute_diff(current, desired):
    """
    Ist- und Soll-Zustand vergleichen (Reihenfolge egal).
    Liefert (to_add, to_remove, unchanged).
    """

    current_set = {normalize_address(a) for a in current}
    desired_set = {normalize_address(a) for a in desired}

    to_add = [a for a in desired if normalize_address(a) not in current_set]
    to_remove = [a for a in current if normalize_address(a) not in desired_set]
    unchanged = len(current_set & desired_set)

    return to_add, to_remove, unchanged


def settings_mismatch(item):
    """
    Liefert eine Beschreibung der Abweichungen von DESIRED_SETTINGS,
    oder einen leeren String, wenn der Eintrag passt.
    """

    # siteIds wird bewusst nicht verglichen: das Verhalten der API
    # (z.B. ob "alle Sites" als Liste aller IDs gemeldet wird) ist
    # nicht dokumentiert und würde sonst jeden Lauf zu einem Update führen.
    reasons = [
        f"{key}={item.get(key)}"
        for key, value in DESIRED_SETTINGS.items()
        if item.get(key) != value
    ]

    return ", ".join(reasons)


# ------------------------------------------------------------------
# Cisco API
# ------------------------------------------------------------------

def get_access_token(api_key, api_secret):
    """OAuth2 Access Token von Cisco Secure Access holen."""

    response = requests.post(
        TOKEN_URL,
        auth=(api_key, api_secret),
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data={
            "grant_type": "client_credentials"
        },
        timeout=30,
    )

    response.raise_for_status()

    token_data = response.json()
    return token_data["access_token"]


def retry_delay(response, attempt):
    """
    Wartezeit vor dem nächsten Versuch: Retry-After-Header (Sekunden),
    sonst exponentielles Backoff (2, 4, 8, ... max. MAX_RETRY_DELAY).
    """

    header = response.headers.get("Retry-After", "")

    try:
        delay = float(header)
    except ValueError:
        delay = 2 ** (attempt + 1)

    return min(max(delay, 1), MAX_RETRY_DELAY)


def rate_limit_delay(response, attempt):
    """
    Wartezeit nach HTTP 429: 60, 120, 240, 300, 300, ... Sekunden.
    Ein längerer Retry-After-Header hat Vorrang.
    """

    delay = min(RATE_LIMIT_DELAY * 2 ** attempt, RATE_LIMIT_MAX_DELAY)

    try:
        delay = max(delay, float(response.headers.get("Retry-After", "")))
    except ValueError:
        pass

    return delay


def print_api_error(response):
    print(color("\nCisco API Fehler:", RED))
    print(f"{response.request.method} {response.url}")
    print(f"HTTP {response.status_code}")
    print(response.text)


def api_request(method, url, token, payload=None, params=None,
                retry_on=RETRY_STATUS, allowed=(), quiet=False):
    """
    Request an die Cisco API senden, JSON-Antwort zurückgeben.

    retry_on: Status-Codes, bei denen automatisch wiederholt wird.
    allowed:  Status-Codes, die nicht als Fehler gelten (Rückgabe None).
    quiet:    Fehlerdetails nicht ausgeben (Aufrufer entscheidet selbst).
    """

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    if payload is not None:
        headers["Content-Type"] = "application/json"

    error_attempt = 0
    rate_attempt = 0
    rate_waited = 0

    while True:
        response = requests.request(
            method,
            url,
            headers=headers,
            json=payload,
            params=params,
            timeout=30,
        )

        status = response.status_code

        if status not in retry_on:
            break

        if status == 429:
            if rate_waited >= RATE_LIMIT_MAX_WAIT:
                break

            delay = rate_limit_delay(response, rate_attempt)
            rate_attempt += 1
            rate_waited += delay
            progress = (f"Rate Limit, bisher {rate_waited / 60:.0f} "
                        f"von max. {RATE_LIMIT_MAX_WAIT / 60:.0f} min")
        else:
            if error_attempt == MAX_RETRIES:
                break

            delay = retry_delay(response, error_attempt)
            error_attempt += 1
            progress = f"Versuch {error_attempt}/{MAX_RETRIES}"

        print(color(
            f"  HTTP {status} - warte {delay:.0f}s ({progress})...", GREY
        ))
        time.sleep(delay)

    if response.status_code in allowed:
        return None

    if not response.ok:
        if not quiet:
            print_api_error(response)
        response.raise_for_status()

    if response.status_code == 204 or not response.content:
        return None

    return response.json()


def extract_items(body):
    """
    Liste der Einträge aus einer Antwort holen. Laut Doku ist die Antwort
    ein Array; zur Sicherheit werden auch übliche Hüllen akzeptiert.
    """

    if body is None:
        return []

    if isinstance(body, list):
        return body

    if isinstance(body, dict):
        for key in ("data", "items", "internalDomains", "results"):
            if isinstance(body.get(key), list):
                return body[key]

    raise RuntimeError(
        f"Unerwartetes Antwortformat der Internal-Domains-API: "
        f"{type(body).__name__} {str(body)[:200]}"
    )


def list_internal_domains(token):
    """
    Alle Internal Domains laden (paginiert).

    Es wird so lange weitergeblättert, bis eine Seite leer ist - nicht
    nur bis eine Seite weniger als PAGE_LIMIT Einträge hat, denn die API
    kann weniger pro Seite liefern als angefragt. Liefert die API eine
    Seite erneut (page-Parameter ignoriert), wird abgebrochen.
    """

    items = []
    seen_ids = set()
    page = 1

    while True:
        body = api_request(
            "GET",
            INTERNAL_DOMAINS_URL,
            token,
            params={"page": page, "limit": PAGE_LIMIT},
        )
        batch = extract_items(body)

        if DEBUG:
            print(color(
                f"  [debug] Seite {page}: {len(batch)} Einträge "
                f"(Antworttyp {type(body).__name__})", GREY
            ))

        if not batch:
            return items

        new = [item for item in batch if item.get("id") not in seen_ids]

        if not new:
            # Gleiche Einträge wie zuvor: API ignoriert die Pagination.
            # Die Liste wäre unvollständig -> lieber abbrechen, als
            # vorhandene Einträge als "fehlt" zu behandeln.
            raise RuntimeError(
                f"Internal-Domains-API liefert auf Seite {page} dieselben "
                f"Einträge wie zuvor - Liste kann nicht vollständig geladen "
                f"werden ({len(items)} bisher). Abbruch ohne Änderungen."
            )

        for item in new:
            seen_ids.add(item.get("id"))

        items.extend(new)
        page += 1


def find_internal_domain(token, domain):
    """Aktuellen Eintrag zu einer Domain direkt bei Cisco nachschlagen."""

    for item in list_internal_domains(token):
        if normalize_address(item.get("domain", "")) == normalize_address(domain):
            return item

    return None


def create_internal_domain(token, domain):
    """
    Internal Domain anlegen, sofern sie nicht bereits existiert.
    Liefert True, wenn angelegt, False, wenn sie schon vorhanden war.

    POST ist nicht idempotent: automatisch wiederholt wird nur bei 429
    (Request wurde nicht verarbeitet). Bei anderen Fehlern (z.B. Konflikt
    oder 5xx, bei dem der Eintrag trotzdem angelegt worden sein kann)
    wird bei Cisco nachgesehen, ob die Domain inzwischen existiert.
    """

    payload = {"domain": domain, **DESIRED_SETTINGS}

    try:
        api_request(
            "POST", INTERNAL_DOMAINS_URL, token, payload=payload,
            retry_on=(429,), quiet=True,
        )
        return True
    except requests.HTTPError as exc:
        if find_internal_domain(token, domain):
            print(color(
                f"  {domain} existiert bereits - wird nicht erneut angelegt.",
                GREY,
            ))
            return False
        print_api_error(exc.response)
        raise


def update_internal_domain(token, item):
    """Bestehenden Eintrag auf DESIRED_SETTINGS bringen."""

    payload = {"domain": item["domain"], **DESIRED_SETTINGS}

    if item.get("description"):
        payload["description"] = item["description"]

    return api_request(
        "PUT", f"{INTERNAL_DOMAINS_URL}/{item['id']}", token, payload=payload
    )


def delete_internal_domain(token, item):
    """Löschen; 404 (bereits gelöscht) gilt als Erfolg."""

    return api_request(
        "DELETE", f"{INTERNAL_DOMAINS_URL}/{item['id']}", token,
        allowed=(404,),
    )


# ------------------------------------------------------------------
# Abgleich
# ------------------------------------------------------------------

def plan_changes(current_items, desired):
    """
    Ermittelt die notwendigen Änderungen.
    Liefert (to_add, to_remove, to_update, unchanged) - to_remove und
    to_update enthalten die API-Objekte, to_add die Domain-Namen.
    """

    by_domain = {}
    for item in current_items:
        by_domain.setdefault(normalize_address(item.get("domain", "")), []).append(item)

    to_add, removed_names, _ = compute_diff(list(by_domain), desired)

    to_remove = []
    for name in removed_names:
        to_remove.extend(by_domain[name])

    to_update = []
    unchanged = 0

    for name in desired:
        items = by_domain.get(name)
        if not items:
            continue

        # Duplikate derselben Domain: ersten behalten, Rest löschen
        keep, extra = items[0], items[1:]
        to_remove.extend(extra)

        if settings_mismatch(keep):
            to_update.append(keep)
        else:
            unchanged += 1

    return to_add, to_remove, to_update, unchanged


def plan_signature(to_add, to_remove, to_update):
    """Vergleichbare Kurzform eines Änderungsplans."""

    return (
        sorted(to_add),
        sorted(item.get("id") for item in to_remove),
        sorted(item.get("id") for item in to_update),
    )


def print_changes(to_add, to_remove, to_update, unchanged):
    print(color(f"\nUnverändert: {unchanged}", GREY))

    for domain in to_add:
        print(color(f"  + {domain}", GREEN))

    for item in to_remove:
        print(color(f"  - {item.get('domain')}", RED))

    for item in to_update:
        print(color(
            f"  ~ {item.get('domain')} ({settings_mismatch(item)})", YELLOW
        ))

    print_summary(to_add, to_remove, to_update)


def print_summary(to_add, to_remove, to_update):
    print(
        f"\nHinzufügen: {color(str(len(to_add)), GREEN)}  "
        f"Löschen: {color(str(len(to_remove)), RED)}  "
        f"Anpassen: {color(str(len(to_update)), YELLOW)}"
    )


def print_status_report(current_items, desired, to_remove, to_update):
    """
    Für jede Domain aus der Datei ausgeben, ob sie bei Cisco existiert,
    danach alle Einträge, die nur bei Cisco existieren.
    """

    by_domain = {}
    for item in current_items:
        by_domain.setdefault(normalize_address(item.get("domain", "")), []).append(item)

    update_ids = {item.get("id") for item in to_update}
    width = max((len(d) for d in desired), default=0)

    print("\nAbgleich Datei -> Cisco:")

    for domain in desired:
        items = by_domain.get(domain)
        name = domain.ljust(width)

        if not items:
            print(color(f"  + {name}  fehlt           -> wird angelegt", GREEN))
            continue

        keep = items[0]

        if keep.get("id") in update_ids:
            print(color(
                f"  ~ {name}  existiert (id {keep.get('id')}), abweichend: "
                f"{settings_mismatch(keep)} -> wird angepasst", YELLOW
            ))
        else:
            print(color(
                f"  = {name}  existiert (id {keep.get('id')})", GREY
            ))

    if to_remove:
        print("\nNur bei Cisco bzw. doppelt vorhanden:")

        for item in to_remove:
            print(color(
                f"  - {item.get('domain')}  (id {item.get('id')}) "
                f"-> wird gelöscht", RED
            ))


def find_matches(items, domain):
    """Exakte und ähnliche Treffer für domain in einer Liste von Einträgen."""

    target = normalize_address(domain)
    exact, similar = [], []

    for item in items:
        other = normalize_address(str(item.get("domain") or ""))

        if other == target:
            exact.append(item)
        elif other and (target in other or other in target):
            similar.append(item)

    return exact, similar


def print_matches(exact, similar):
    if exact:
        for item in exact:
            print(color("  GEFUNDEN:", GREEN))
            print(color("    " + json.dumps(item, indent=2).replace("\n", "\n    "), GREEN))
    else:
        print(color("  NICHT GEFUNDEN", RED))

    for item in similar:
        print(color(
            f"  ähnlich: {item.get('domain')!r} (id {item.get('id')}, "
            f"domainType {item.get('domainType', '-')})", YELLOW
        ))


def check_domain(token, domain, org_id):
    """
    Read-only Diagnose: existiert domain bei Cisco?
    Prüft die offizielle API und die (undokumentierte) Portal-Liste.
    """

    print(f"\nPrüfe {domain!r} (normalisiert: {normalize_address(domain)!r})")

    print("\n[1] Offizielle API: " + INTERNAL_DOMAINS_URL)
    official = list_internal_domains(token)
    print(f"  {len(official)} Einträge geladen")
    print_matches(*find_matches(official, domain))

    url = PORTAL_DOMAINS_URL.format(org_id=org_id)
    print("\n[2] Portal-Liste (GUI, undokumentiert, nur lesend): " + url)

    response = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        timeout=30,
    )

    if not response.ok:
        print(color(
            f"  HTTP {response.status_code} - Portal-Liste mit API-Key nicht "
            f"abrufbar: {response.text[:300]}", YELLOW
        ))
        return

    try:
        portal = extract_items(response.json())
    except (ValueError, RuntimeError) as exc:
        print(color(f"  Antwort nicht auswertbar: {exc}", YELLOW))
        return

    print(f"  {len(portal)} Einträge geladen (ggf. nur erste Seite)")

    types = {}
    for item in portal:
        key = item.get("domainType", "-")
        types[key] = types.get(key, 0) + 1
    print(f"  domainType-Verteilung: {types}")

    print_matches(*find_matches(portal, domain))


def print_debug(current_items, to_add):
    """Rohdaten zur Fehlersuche: was liefert Cisco tatsächlich?"""

    print(color("\n[debug] Von Cisco gelieferte Einträge (roh):", GREY))

    if current_items:
        print(color(f"  Felder: {sorted(current_items[0].keys())}", GREY))

    for item in current_items:
        print(color(
            f"  id={item.get('id')!r:<12} domain={item.get('domain')!r}", GREY
        ))

    if not to_add:
        return

    print(color("\n[debug] Als fehlend erkannt - ähnliche Einträge bei Cisco:", GREY))

    for domain in to_add:
        similar = []
        for item in current_items:
            other = str(item.get("domain") or "").lower().strip()
            if other and (domain in other or other in domain):
                similar.append(item.get("domain"))
        print(color(f"  {domain!r}: {similar or 'keine'}", GREY))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Internal Domains (Bypass Secure Access) mit "
                    "trafficUrls.txt abgleichen."
    )
    parser.add_argument(
        "-y", "--yes", action="store_true",
        help="Änderungen ohne Rückfrage durchführen",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Nur Unterschiede anzeigen, nichts ändern",
    )
    parser.add_argument(
        "--file", default=DEFAULT_URLS_FILE,
        help="Datei mit dem Soll-Zustand (Default: trafficUrls.txt)",
    )
    parser.add_argument(
        "--secrets-file", metavar="FILE",
        help="Datei mit den Credentials (Default: secrets.env "
             "neben dem Script)",
    )
    parser.add_argument(
        "--allow-empty", action="store_true",
        help="Leere Soll-Liste erlauben (löscht alle Internal Domains)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Ausgabe ohne Farben",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Rohdaten der Cisco-Antwort ausgeben (Fehlersuche)",
    )
    parser.add_argument(
        "--check", metavar="DOMAIN",
        help="Nur prüfen, ob DOMAIN bei Cisco existiert (offizielle API "
             "und Portal-Liste), nichts ändern",
    )
    parser.add_argument(
        "--org-id", type=int, default=ORG_ID,
        help=f"Organisations-ID für die Portal-Liste bei --check "
             f"(Default: {ORG_ID})",
    )
    return parser.parse_args()


def main():

    global DEBUG

    args = parse_args()
    setup_color(args.no_color)
    DEBUG = args.debug

    try:
        secrets_file = args.secrets_file or SECRETS_FILE

        # Explizit angegebene Datei muss existieren; die Default-Datei
        # darf fehlen, wenn die Credentials als Umgebungsvariablen kommen.
        if args.secrets_file and not os.path.isfile(secrets_file):
            print(color(
                f"Fehler: Secrets-Datei {secrets_file} nicht gefunden.", RED
            ))
            sys.exit(1)

        secrets = load_secrets(secrets_file)
        api_key = secrets.get("CISCO_SECURE_ACCESS_KEY")
        api_secret = secrets.get("CISCO_SECURE_ACCESS_SECRET")

        if not api_key or not api_secret:
            print(color(
                "Fehler: CISCO_SECURE_ACCESS_KEY und "
                "CISCO_SECURE_ACCESS_SECRET müssen gesetzt sein "
                f"(Umgebungsvariablen oder {secrets_file}, "
                "siehe secrets.env.example).", RED
            ))
            sys.exit(1)

        if args.check:
            print("Hole OAuth Token...")
            check_domain(
                get_access_token(api_key, api_secret), args.check, args.org_id
            )
            return

        desired = load_desired_addresses(args.file)

        if not desired and not args.allow_empty:
            print(color(
                f"Fehler: {args.file} enthält keine Einträge. "
                "Das würde alle Internal Domains löschen. "
                "Mit --allow-empty erzwingen.", RED
            ))
            sys.exit(1)

        print("Hole OAuth Token...")
        token = get_access_token(api_key, api_secret)

        print("Lade Internal Domains...")
        current_items = list_internal_domains(token)
        print(f"Vorhanden: {len(current_items)}, Soll: {len(desired)}")

        to_add, to_remove, to_update, unchanged = plan_changes(
            current_items, desired
        )

        if DEBUG:
            print_debug(current_items, to_add)

        if args.dry_run:
            # Vollständiger Status: jede Domain aus der Datei mit
            # Ergebnis der Prüfung, ob sie bei Cisco existiert.
            print_status_report(current_items, desired, to_remove, to_update)
            print(color(f"\nExistiert bereits: {unchanged + len(to_update)}", GREY))
            print_summary(to_add, to_remove, to_update)
        else:
            print_changes(to_add, to_remove, to_update, unchanged)

        if not to_add and not to_remove and not to_update:
            print(color("\nKeine Änderungen notwendig.", GREEN))
            return

        if args.dry_run:
            print(color("\nDry-Run: keine Änderungen durchgeführt.", YELLOW))
            return

        if not args.yes:
            answer = input("\nÄnderungen wirklich durchführen? [y/N]: ")

            if answer.lower() not in ("y", "yes", "j", "ja"):
                print("Abgebrochen.")
                return

        # Unmittelbar vor dem Schreiben erneut prüfen, was bei Cisco
        # existiert - seit der ersten Abfrage kann sich etwas geändert haben.
        print("\nPrüfe aktuellen Stand erneut...")
        confirmed = plan_signature(to_add, to_remove, to_update)
        to_add, to_remove, to_update, unchanged = plan_changes(
            list_internal_domains(token), desired
        )

        if not to_add and not to_remove and not to_update:
            print(color("Keine Änderungen mehr notwendig.", GREEN))
            return

        if plan_signature(to_add, to_remove, to_update) != confirmed:
            print(color(
                "Der Stand bei Cisco hat sich geändert, neue Änderungen:",
                YELLOW,
            ))
            print_changes(to_add, to_remove, to_update, unchanged)

            if not args.yes:
                answer = input("\nDiese Änderungen durchführen? [y/N]: ")

                if answer.lower() not in ("y", "yes", "j", "ja"):
                    print("Abgebrochen.")
                    return

        print()

        for item in to_remove:
            delete_internal_domain(token, item)
            print(color(f"  gelöscht:   {item.get('domain')}", RED))

        for item in to_update:
            update_internal_domain(token, item)
            print(color(f"  angepasst:  {item.get('domain')}", YELLOW))

        for domain in to_add:
            if create_internal_domain(token, domain):
                print(color(f"  angelegt:   {domain}", GREEN))

        print("\nPrüfe Ergebnis...")
        to_add, to_remove, to_update, _ = plan_changes(
            list_internal_domains(token), desired
        )

        if to_add or to_remove or to_update:
            print(color(
                "\nWarnung: Cisco meldet einen abweichenden Zustand:", YELLOW
            ))
            print_changes(to_add, to_remove, to_update, 0)
            sys.exit(1)

        print(color("\nAbgleich erfolgreich.", GREEN))

    except requests.HTTPError as exc:
        print(color(f"\nHTTP Fehler: {exc}", RED))
        sys.exit(1)

    except Exception as exc:
        print(color(f"\nFehler: {exc}", RED))
        sys.exit(1)


if __name__ == "__main__":
    main()
