#!/usr/bin/env python3
"""
Ruft jede Adresse aus urlList.txt auf und prüft, ob echter Content oder
die Blocking Page von Cisco Secure Access zurückkommt. Ergebnis als
HTML-Report.

Optional wird je FQDN die Kategorisierung über die Secure Access
Investigate API abgefragt und zusätzlich als CSV (fqdn,kategorie)
ausgegeben.

API:   https://api.sse.cisco.com/investigate/v2/domains/categorization/{domain}
Scope: investigate.investigate:read
"""

import os
import re
import sys
import csv
import html
import time
import socket
import argparse
import ipaddress
from datetime import datetime
from urllib.parse import urlsplit, quote
from concurrent.futures import ThreadPoolExecutor

# Stellt load_secrets, get_access_token, api_request und die farbige
# Ausgabe bereit; aktiviert beim Import truststore (TLS-Inspection).
import trafficSteering as ts
import requests
import urllib3

# Ungeprüfte HTTPS-Aufrufe sind gewollt (Wiederholung nach Zertifikats-
# fehler bzw. --insecure); der Zertifikatsstatus steht im Report.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LIST_FILE = os.path.join(SCRIPT_DIR, "urlList.txt")
DEFAULT_OUT_DIR = os.path.join(SCRIPT_DIR, "reports")

CATEGORIZATION_URL = (
    f"{ts.BASE_URL}/investigate/v2/domains/categorization/{{domain}}?showLabels"
)

# ------------------------------------------------------------------
# Erkennung der Blocking Page - bei Bedarf an die eigene (angepasste)
# Block Page anpassen. Vergleich jeweils ohne Groß-/Kleinschreibung.
# ------------------------------------------------------------------

# Weiterleitung auf einen dieser Hosts (oder Subdomain davon) = Block Page
# (z. B. malware.block.sse.cisco.com)
BLOCK_HOST_MARKERS = (
    "block.sse.cisco.com",
    "block.opendns.com",
)

# Netze der Cisco Block Pages (DNS-Layer-Block löst auf diese IPs auf)
BLOCK_NETWORKS = [
    ipaddress.ip_network("146.112.61.0/24"),
]

# Einer dieser Texte im Body kennzeichnet die Block Page. Bewusst nur
# eindeutige Merkmale: allgemeine Wörter wie "blocked" oder "OpenDNS"
# kommen auch auf normalen Seiten vor (z. B. internetbadguys.com).
BLOCK_BODY_MARKERS = (
    "block.sse.cisco.com",
    "<dt>block page id</dt>",
)

# Fehlerseiten, die der Proxy statt des Contents liefert (z. B. HTTP 515
# "Upstream Certificate Untrusted") - Ziel nicht erreicht, aber kein
# Block durch eine Policy-Regel.
PROXY_ERROR_MARKERS = (
    "this page is served by cisco secure access",
    "the requested url could not be retrieved",
)

# Block Type (Diagnostic Info der Block Page), der als Warnung gilt
WARN_BLOCK_TYPES = (
    "warn",
)

STATUS_OK = "OK"
STATUS_BLOCKED = "BLOCKIERT"
STATUS_WARN = "WARNUNG"
STATUS_ERROR = "FEHLER"
STATUSES = (STATUS_OK, STATUS_BLOCKED, STATUS_WARN, STATUS_ERROR)

STATUS_COLORS = {
    STATUS_OK: ts.GREEN,
    STATUS_BLOCKED: ts.RED,
    STATUS_WARN: ts.YELLOW,
    STATUS_ERROR: ts.GREY,
}

CERT_VALID = "gültig"
CERT_INVALID = "ungültig"
CERT_UNCHECKED = "nicht geprüft"

DOMAIN_STATUS = {
    1: "sicher",
    0: "unbestimmt",
    -1: "bösartig",
}

MAX_BODY_BYTES = 512 * 1024

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


class CategorizationDenied(Exception):
    """Investigate API verweigert den Zugriff (Lizenz oder Scope fehlt)."""


class ApiUnreachable(Exception):
    """Investigate API nach Wiederholungen nicht erreichbar (Netzwerk)."""


# Wiederholungen bei Netzwerkfehlern gegen die API und Abbruch der
# Kategorisierung nach so vielen Fehlschlägen in Folge
API_NET_RETRIES = 2
MAX_API_FAILURES = 3


# ------------------------------------------------------------------
# Eingaben
# ------------------------------------------------------------------

def load_entries(path):
    """
    Adressen aus der Datei lesen: FQDN, IP-Adresse oder vollständige URL.
    Leerzeilen und #-Kommentare werden ignoriert, Duplikate entfernt.
    """

    entries = []
    seen = set()

    with open(path, encoding="utf-8-sig") as handle:
        for line in handle:
            entry = line.split("#", 1)[0].strip()

            if not entry:
                continue

            key = entry.lower().rstrip("/")

            if key not in seen:
                seen.add(key)
                entries.append(entry)

    return entries


def parse_entry(entry):
    """
    Liefert (host, is_ip, urls). Ohne Schema wird zuerst https, dann
    http versucht; mit Schema nur die angegebene URL.
    """

    try:
        ip = ipaddress.ip_address(entry.strip("[]"))
        host = str(ip)
        netloc = f"[{host}]" if ip.version == 6 else host
        return host, True, [f"https://{netloc}/", f"http://{netloc}/"]
    except ValueError:
        pass

    if "://" in entry:
        host = urlsplit(entry).hostname or entry
        urls = [entry]
    else:
        rest = entry if "/" in entry else entry + "/"
        host = urlsplit("https://" + rest).hostname or entry
        urls = ["https://" + rest, "http://" + rest]

    host = ts.normalize_address(host)

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    return host, is_ip, urls


# ------------------------------------------------------------------
# Seitenaufruf und Klassifizierung
# ------------------------------------------------------------------

def resolve(host):
    """Aufgelöste IP-Adressen (leere Liste und Fehlertext bei DNS-Fehler)."""

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return [], f"DNS: {exc}"

    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)

    return ips, ""


def in_block_network(ips):
    """Erste IP, die in einem Cisco-Block-Netz liegt, sonst None."""

    for ip in ips:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue

        if any(address in net for net in BLOCK_NETWORKS if address.version == net.version):
            return ip

    return None


def is_block_host(host):
    host = (host or "").lower()
    return any(host == m or host.endswith("." + m) for m in BLOCK_HOST_MARKERS)


def read_body(response):
    """Body bis MAX_BODY_BYTES lesen und als Text liefern."""

    data = b""

    for chunk in response.iter_content(65536):
        data += chunk
        if len(data) >= MAX_BODY_BYTES:
            break

    response.close()
    return data.decode(response.encoding or "utf-8", errors="replace")


def extract_title(body):
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)

    if not match:
        return ""

    title = " ".join(html.unescape(match.group(1)).split())
    return title[:150]


def find_word(text, words):
    for word in words:
        if word.lower() in text:
            return word
    return None


def block_page_info(body):
    """Diagnostic Info der Block Page (<dt>Name</dt><dd>Wert</dd>) als dict."""

    info = {}

    for name, value in re.findall(
        r"<dt>\s*(.*?)\s*</dt>\s*<dd>\s*(.*?)\s*</dd>", body, re.DOTALL
    ):
        info[html.unescape(name).lower()] = " ".join(html.unescape(value).split())

    return info


def strip_tags(fragment):
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", fragment)).split())


def proxy_error_detail(body):
    """Fehlertext einer Proxy-Fehlerseite, z. B. '515 Upstream Certificate Untrusted'."""

    for pattern in (
        r'class="redbold"[^>]*>(.*?)</p>',
        r"error was encountered:\s*(.*?)</p>",
    ):
        match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
        if match and strip_tags(match.group(1)):
            return strip_tags(match.group(1))[:150]

    return extract_title(body)


def describe_block(info):
    """Kurzbeschreibung aus der Diagnostic Info: Block Type und Regel."""

    parts = []

    if info.get("block type"):
        parts.append(f"Block Type: {info['block type']}")

    if info.get("rule name"):
        rule = f"Regel: {info['rule name']}"
        if info.get("rule id"):
            rule += f" (ID {info['rule id']})"
        parts.append(rule)

    return ", ".join(parts)


def classify(host, chain, body, block_ip, extra_markers):
    """
    Antwort einordnen. Liefert (status, grund).
    chain: alle aufgerufenen URLs inkl. Weiterleitungen.
    """

    reason = ""

    for url in chain[1:]:
        redirect_host = urlsplit(url).hostname
        if is_block_host(redirect_host) and not is_block_host(host):
            reason = f"Weiterleitung auf {redirect_host}"
            break

    text = body.lower()

    if not reason:
        marker = find_word(text, BLOCK_BODY_MARKERS + tuple(extra_markers))
        if marker:
            reason = f"Marker: {marker!r}"

    if not reason and block_ip:
        reason = f"DNS-Block: {host} löst auf Cisco-Block-IP {block_ip} auf"

    if not reason:
        if find_word(text, PROXY_ERROR_MARKERS):
            return STATUS_ERROR, f"Fehlerseite des Proxys: {proxy_error_detail(body)}"
        return STATUS_OK, ""

    info = block_page_info(body)
    details = describe_block(info)

    if details:
        reason += f"; {details}"

    block_type = info.get("block type", "").lower()
    redirect_host = (urlsplit(chain[-1]).hostname or "").lower()

    if any(t in block_type or redirect_host.startswith(t + ".")
           for t in WARN_BLOCK_TYPES):
        return STATUS_WARN, reason

    return STATUS_BLOCKED, reason


def short_error(exc):
    """Kompakte Fehlermeldung aus einer requests-Exception."""

    if isinstance(exc, requests.exceptions.SSLError):
        prefix = "TLS-Fehler"
    elif isinstance(exc, requests.exceptions.Timeout):
        prefix = "Timeout"
    elif isinstance(exc, requests.exceptions.ProxyError):
        prefix = "Proxy-Fehler"
    elif isinstance(exc, requests.exceptions.ConnectionError):
        prefix = "Verbindungsfehler"
    else:
        prefix = type(exc).__name__

    # Eigentliche Ursache aus der urllib3-Hülle holen (MaxRetryError.reason),
    # ohne Objekt-Reprs wie "<urllib3.connection...object at 0x...>"
    inner = exc.args[0] if exc.args else exc
    inner = getattr(inner, "reason", inner)
    messages = [a for a in getattr(inner, "args", ()) if isinstance(a, str)]
    detail = messages[-1] if messages else str(inner)
    detail = re.sub(r"^\w+ConnectionPool\([^)]*\):\s*", "", detail)

    return f"{prefix}: {detail[:200]}"


def fetch(url, options):
    """
    Seite abrufen. Liefert (response, body, zertifikat).

    Bei einem Zertifikatsfehler wird ohne Prüfung wiederholt, damit der
    Inhalt trotzdem bewertet werden kann; der Fehler steht dann in
    'zertifikat' und damit im Report.
    """

    kwargs = {
        "headers": {"User-Agent": USER_AGENT},
        "timeout": options.timeout,
        "allow_redirects": True,
        "stream": True,
        "proxies": options.proxies,
    }

    if options.insecure:
        response = requests.get(url, verify=False, **kwargs)
        cert = CERT_UNCHECKED
    else:
        try:
            response = requests.get(url, **kwargs)
            cert = CERT_VALID
        except requests.exceptions.SSLError as exc:
            cert = f"{CERT_INVALID}: {short_error(exc).split(': ', 1)[-1]}"
            response = requests.get(url, verify=False, **kwargs)

    return response, read_body(response), cert


def check_entry(entry, options):
    """Eine Adresse aufrufen und das Ergebnis als dict liefern."""

    host, is_ip, urls = parse_entry(entry)

    result = {
        "input": entry,
        "host": host,
        "is_ip": is_ip,
        "url": urls[0],
        "status": STATUS_ERROR,
        "http": "",
        "final_url": "",
        "ips": [],
        "title": "",
        "cert": "",
        "reason": "",
        "category": "",
        "domain_status": "",
    }

    if is_ip:
        result["ips"] = [host]
        dns_error = ""
    else:
        result["ips"], dns_error = resolve(host)

    block_ip = in_block_network(result["ips"])
    errors = []

    # Ohne Proxy kann ein lokal nicht auflösbarer Host nicht erreicht werden
    # (mit Proxy löst der Proxy auf - dann trotzdem aufrufen).
    if dns_error and not (options.proxies or requests.utils.get_environ_proxies(urls[0])):
        result["reason"] = dns_error
        return result

    for url in urls:
        result["url"] = url

        try:
            response, body, cert = fetch(url, options)
        except requests.exceptions.RequestException as exc:
            errors.append(f"{urlsplit(url).scheme.upper()}: {short_error(exc)}")
            continue

        chain = [r.url for r in response.history] + [response.url]

        # Zertifikat nur relevant, wenn HTTPS im Spiel war
        if any(u.lower().startswith("https://") for u in chain):
            result["cert"] = cert

        result["http"] = response.status_code
        result["final_url"] = response.url
        result["title"] = extract_title(body)
        result["status"], reason = classify(
            host, chain, body, block_ip, options.markers
        )
        result["reason"] = "; ".join(errors + ([reason] if reason else []))

        if options.save_bodies:
            save_body(options.save_bodies, host, body)

        return result

    # Kein Aufruf erfolgreich
    if block_ip:
        result["status"] = STATUS_BLOCKED
        errors.insert(0, f"DNS-Block: löst auf Cisco-Block-IP {block_ip} auf")
    elif dns_error:
        errors.insert(0, dns_error)

    result["reason"] = "; ".join(errors)
    return result


def save_body(directory, host, body):
    os.makedirs(directory, exist_ok=True)
    name = re.sub(r"[^\w.-]", "_", host) + ".html"

    with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
        handle.write(body)


# ------------------------------------------------------------------
# Kategorisierung (Investigate API)
# ------------------------------------------------------------------

def api_request_with_retry(url, token):
    """
    GET an die API; Netzwerkfehler (Timeout, Verbindungsabbruch) werden
    API_NET_RETRIES-mal wiederholt, danach ApiUnreachable.
    HTTP-Fehler gibt ts.api_request als requests.HTTPError weiter.
    """

    for attempt in range(API_NET_RETRIES + 1):
        try:
            return ts.api_request("GET", url, token, quiet=True)
        except requests.HTTPError:
            raise
        except requests.RequestException as exc:
            if attempt == API_NET_RETRIES:
                raise ApiUnreachable(short_error(exc)) from exc

            print(ts.color(
                f"  {short_error(exc)} - Wiederholung "
                f"{attempt + 1}/{API_NET_RETRIES}...", ts.GREY
            ))
            time.sleep(2 * (attempt + 1))

def categorize(token, domain):
    """
    Kategorien einer Domain. Liefert (kategorie, domain_status).
    Wirft CategorizationDenied bei 401/403 und ApiUnreachable, wenn die
    API auch nach Wiederholungen nicht erreichbar ist.
    """

    url = CATEGORIZATION_URL.format(domain=quote(domain, safe=""))

    try:
        body = api_request_with_retry(url, token)
    except requests.HTTPError as exc:
        code = exc.response.status_code

        if code in (401, 403):
            raise CategorizationDenied(
                f"HTTP {code} {exc.response.text[:200]}"
            ) from exc

        if code == 404:
            return "unbekannt", ""

        return f"Fehler: HTTP {code}", ""

    info = {}
    if isinstance(body, dict):
        info = body.get(domain) or next(iter(body.values()), {}) or {}

    labels = list(info.get("content_categories") or [])
    labels += [c for c in info.get("security_categories") or [] if c not in labels]

    category = "; ".join(str(c) for c in labels) or "unkategorisiert"
    domain_status = DOMAIN_STATUS.get(info.get("status"), "")

    return category, domain_status


def categorize_all(token, results):
    """
    Kategorien für alle Einträge setzen (je Host nur eine Abfrage).
    Liefert False, wenn die API den Zugriff verweigert.

    Ist die API nicht erreichbar, steht beim Eintrag "Fehler: ..."; nach
    MAX_API_FAILURES Fehlschlägen in Folge werden die restlichen
    Einträge nicht mehr abgefragt.
    """

    cache = {}
    failures = 0

    for result in results:
        host = result["host"]

        if result["is_ip"]:
            result["category"] = "IP - keine Kategorisierung"
            continue

        if host not in cache:
            if failures >= MAX_API_FAILURES:
                cache[host] = ("Fehler: API nicht erreichbar - nicht abgefragt", "")
            else:
                try:
                    cache[host] = categorize(token, host)
                    failures = 0
                except ApiUnreachable as exc:
                    failures += 1
                    cache[host] = (f"Fehler: {exc}", "")

                    if failures >= MAX_API_FAILURES:
                        print(ts.color(
                            f"\nInvestigate API {failures}x in Folge nicht "
                            "erreichbar - restliche Einträge werden nicht "
                            "abgefragt.", ts.YELLOW
                        ))
                except CategorizationDenied as exc:
                    print(ts.color(
                        f"\nInvestigate API verweigert den Zugriff ({exc}).\n"
                        "Der API-Key benötigt den Scope investigate.investigate:read "
                        "und eine Investigate-Lizenz. Kategorien werden übersprungen.",
                        ts.YELLOW,
                    ))
                    for r in results:
                        r["category"] = r["domain_status"] = ""
                    return False

            failed = cache[host][0].startswith("Fehler")
            print(ts.color(f"  {host}: {cache[host][0]}", ts.YELLOW if failed else ts.GREY))

        result["category"], result["domain_status"] = cache[host]

    return True


def get_token(args):
    """
    OAuth Token für die Investigate API, oder None, wenn keine
    Credentials vorhanden sind bzw. die Anmeldung fehlschlägt.
    """

    secrets_file = args.secrets_file or ts.SECRETS_FILE

    if args.secrets_file and not os.path.isfile(secrets_file):
        print(ts.color(f"Fehler: Secrets-Datei {secrets_file} nicht gefunden.", ts.RED))
        sys.exit(1)

    secrets = ts.load_secrets(secrets_file)
    api_key = secrets.get("CISCO_SECURE_ACCESS_KEY")
    api_secret = secrets.get("CISCO_SECURE_ACCESS_SECRET")

    if not api_key or not api_secret:
        print(ts.color(
            "Keine Credentials (CISCO_SECURE_ACCESS_KEY/_SECRET) gefunden - "
            "Kategorisierung wird übersprungen.", ts.YELLOW
        ))
        return None

    try:
        return ts.get_access_token(api_key, api_secret)
    except requests.RequestException as exc:
        print(ts.color(
            f"Anmeldung an der Cisco API fehlgeschlagen ({exc}) - "
            "Kategorisierung wird übersprungen.", ts.YELLOW
        ))
        return None


# ------------------------------------------------------------------
# Ausgabe
# ------------------------------------------------------------------

def print_result(result):
    status = result["status"].ljust(9)
    line = f"  {status} {result['input']}"

    if result["http"]:
        line += f"  (HTTP {result['http']})"

    if result["reason"]:
        line += f"  {result['reason']}"

    if result["cert"].startswith(CERT_INVALID):
        line += f"  [Zertifikat {result['cert']}]"

    print(ts.color(line, STATUS_COLORS[result["status"]]))


def write_csv(path, results):
    """CSV mit den Spalten fqdn,kategorie (je Host eine Zeile)."""

    seen = set()

    # utf-8-sig: Excel erkennt die Kodierung (Umlaute)
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, delimiter=",")
        writer.writerow(["fqdn", "kategorie"])

        for result in results:
            if result["host"] in seen:
                continue

            seen.add(result["host"])
            writer.writerow([result["host"], result["category"]])


HTML_TEMPLATE = """<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>URL-Check Report</title>
<style>
:root {
  --bg: #f6f7f9; --panel: #ffffff; --text: #1d2330; --muted: #5f6b7a;
  --border: #dde2e8; --head: #eef1f5;
  --ok: #1a7f37; --ok-bg: #dcf5e3;
  --blocked: #b42318; --blocked-bg: #fde4e1;
  --warn: #9a6700; --warn-bg: #fff3c4;
  --error: #57606a; --error-bg: #e9ecef;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12151b; --panel: #1b2029; --text: #e3e7ee; --muted: #9aa5b4;
    --border: #2c3442; --head: #232a35;
    --ok: #6fdd8b; --ok-bg: #133d22;
    --blocked: #ff8a80; --blocked-bg: #4a1714;
    --warn: #f2cc60; --warn-bg: #3d3110;
    --error: #b6bfca; --error-bg: #2c333d;
  }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 24px 16px; background: var(--bg); color: var(--text);
  font: 14px/1.45 "Segoe UI", system-ui, sans-serif; }
h1 { font-size: 22px; margin: 0 0 4px; }
.meta { color: var(--muted); margin-bottom: 20px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 20px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 12px 18px; min-width: 130px; cursor: pointer; user-select: none; }
.card.active { outline: 2px solid var(--text); }
.card .num { font-size: 26px; font-weight: 600; }
.card .lbl { color: var(--muted); }
.wrap { overflow-x: auto; background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; }
table { border-collapse: collapse; width: 100%; }
th, td { padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left;
  vertical-align: top; }
th { background: var(--head); cursor: pointer; white-space: nowrap; position: sticky; top: 0; }
th.sorted::after { content: " \\25B4"; }
th.sorted.desc::after { content: " \\25BE"; }
td.url { word-break: break-all; min-width: 180px; }
td.reason { color: var(--muted); min-width: 220px; }
td.cert-ok { color: var(--ok); }
td.cert-bad { color: var(--blocked); min-width: 200px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-weight: 600;
  font-size: 12px; white-space: nowrap; }
.s-OK { color: var(--ok); background: var(--ok-bg); }
.s-BLOCKIERT { color: var(--blocked); background: var(--blocked-bg); }
.s-WARNUNG { color: var(--warn); background: var(--warn-bg); }
.s-FEHLER { color: var(--error); background: var(--error-bg); }
.n-OK { color: var(--ok); } .n-BLOCKIERT { color: var(--blocked); }
.n-WARNUNG { color: var(--warn); } .n-FEHLER { color: var(--error); }
</style>
</head>
<body>
<h1>URL-Check Report</h1>
<div class="meta">{meta}</div>
<div class="cards">
{cards}
</div>
<div class="wrap">
<table id="results">
<thead><tr>{headers}</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>
<script>
(function () {
  var table = document.getElementById("results");
  var tbody = table.tBodies[0];
  var cards = document.querySelectorAll(".card");
  var filter = "";

  cards.forEach(function (card) {
    card.addEventListener("click", function () {
      filter = filter === card.dataset.status ? "" : card.dataset.status;
      cards.forEach(function (c) { c.classList.toggle("active", c.dataset.status === filter && filter !== ""); });
      Array.prototype.forEach.call(tbody.rows, function (row) {
        row.style.display = !filter || row.dataset.status === filter ? "" : "none";
      });
    });
  });

  Array.prototype.forEach.call(table.tHead.rows[0].cells, function (th, index) {
    th.addEventListener("click", function () {
      var desc = th.classList.contains("sorted") && !th.classList.contains("desc");
      Array.prototype.forEach.call(table.tHead.rows[0].cells, function (c) { c.classList.remove("sorted", "desc"); });
      th.classList.add("sorted");
      if (desc) th.classList.add("desc");
      var rows = Array.prototype.slice.call(tbody.rows);
      rows.sort(function (a, b) {
        var x = a.cells[index].textContent, y = b.cells[index].textContent;
        var r = x.localeCompare(y, "de", { numeric: true });
        return desc ? -r : r;
      });
      rows.forEach(function (row) { tbody.appendChild(row); });
    });
  });
})();
</script>
</body>
</html>
"""


def cert_class(cert):
    if cert.startswith(CERT_INVALID):
        return "cert-bad"
    if cert == CERT_VALID:
        return "cert-ok"
    return ""


def write_html(path, results, list_file, with_categories, started):
    esc = html.escape
    counts = {s: sum(1 for r in results if r["status"] == s) for s in STATUSES}

    meta = (
        f"Erstellt am {started:%d.%m.%Y %H:%M:%S} &middot; "
        f"Quelle: {esc(os.path.basename(list_file))} &middot; "
        f"{len(results)} Einträge"
    )

    cards = "\n".join(
        f'<div class="card" data-status="{s}">'
        f'<div class="num n-{s}">{counts[s]}</div><div class="lbl">{s.title()}</div></div>'
        for s in STATUSES
    )

    columns = ["Eingabe", "Ergebnis", "HTTP", "Aufgerufene URL", "Finale URL",
               "IP", "Zertifikat", "Seitentitel"]
    if with_categories:
        columns += ["Kategorie", "Domain-Status"]
    columns.append("Grund / Detail")

    headers = "".join(f"<th>{esc(c)}</th>" for c in columns)

    rows = []
    for r in results:
        cells = [
            f"<td>{esc(r['input'])}</td>",
            f'<td><span class="badge s-{r["status"]}">{r["status"]}</span></td>',
            f"<td>{esc(str(r['http']))}</td>",
            f'<td class="url">{esc(r["url"])}</td>',
            f'<td class="url">{esc(r["final_url"])}</td>',
            f"<td>{esc(', '.join(r['ips']))}</td>",
            f'<td class="{cert_class(r["cert"])}">{esc(r["cert"])}</td>',
            f"<td>{esc(r['title'])}</td>",
        ]
        if with_categories:
            cells += [
                f"<td>{esc(r['category'])}</td>",
                f"<td>{esc(r['domain_status'])}</td>",
            ]
        cells.append(f'<td class="reason">{esc(r["reason"])}</td>')

        rows.append(f'<tr data-status="{r["status"]}">{"".join(cells)}</tr>')

    page = (
        HTML_TEMPLATE
        .replace("{meta}", meta)
        .replace("{cards}", cards)
        .replace("{headers}", headers)
        .replace("{rows}", "\n".join(rows))
    )

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(page)


# ------------------------------------------------------------------
# Ablauf
# ------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Adressen aufrufen, Cisco Block Page erkennen und "
                    "HTML-Report (optional Kategorien als CSV) erstellen."
    )
    parser.add_argument(
        "--file", default=DEFAULT_LIST_FILE,
        help="Datei mit einer Adresse (FQDN, IP oder URL) pro Zeile "
             "(Default: urlList.txt)",
    )
    parser.add_argument(
        "--out-dir", default=DEFAULT_OUT_DIR,
        help="Zielverzeichnis für Report und CSV (Default: reports/)",
    )
    parser.add_argument(
        "--secrets-file", metavar="FILE",
        help="Datei mit den Credentials für die Investigate API "
             "(Default: secrets.env neben dem Script)",
    )
    parser.add_argument(
        "--no-categories", action="store_true",
        help="Keine Kategorisierung über die Investigate API",
    )
    parser.add_argument(
        "--categories-only", action="store_true",
        help="Nur Kategorisierung (CSV), keine Seitenaufrufe",
    )
    parser.add_argument(
        "--workers", type=int, default=10,
        help="Anzahl paralleler Seitenaufrufe (Default: 10)",
    )
    parser.add_argument(
        "--timeout", type=float, default=15,
        help="Timeout je Seitenaufruf in Sekunden (Default: 15)",
    )
    parser.add_argument(
        "--proxy", metavar="URL",
        help="Expliziter Proxy, z. B. http://proxy:8080 "
             "(Default: HTTP(S)_PROXY aus der Umgebung)",
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="TLS-Zertifikate gar nicht prüfen (Default: prüfen und bei "
             "Fehler ohne Prüfung wiederholen, Fehler steht im Report)",
    )
    parser.add_argument(
        "--marker", dest="markers", action="append", default=[], metavar="TEXT",
        help="Zusätzlicher Text, der eine Seite als Block Page kennzeichnet "
             "(mehrfach möglich)",
    )
    parser.add_argument(
        "--save-bodies", action="store_true",
        help="Empfangene Seiten unter <out-dir>/bodies/ speichern "
             "(zum Anpassen der Marker)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Ausgabe ohne Farben",
    )

    args = parser.parse_args()

    if args.no_categories and args.categories_only:
        parser.error("--no-categories und --categories-only schließen sich aus")

    return args


def main():
    args = parse_args()
    ts.setup_color(args.no_color)

    args.proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    args.save_bodies = (
        os.path.join(args.out_dir, "bodies") if args.save_bodies else None
    )

    if not os.path.isfile(args.file):
        print(ts.color(f"Fehler: {args.file} nicht gefunden.", ts.RED))
        sys.exit(1)

    entries = load_entries(args.file)

    if not entries:
        print(ts.color(f"Fehler: {args.file} enthält keine Einträge.", ts.RED))
        sys.exit(1)

    started = datetime.now()
    stamp = f"{started:%Y%m%d_%H%M%S}"
    os.makedirs(args.out_dir, exist_ok=True)

    if args.categories_only:
        results = []
        for entry in entries:
            host, is_ip, urls = parse_entry(entry)
            results.append({"input": entry, "host": host, "is_ip": is_ip,
                            "category": "", "domain_status": ""})
    else:
        print(f"Prüfe {len(entries)} Adressen ({args.workers} parallel)...\n")

        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            results = []
            for result in pool.map(lambda e: check_entry(e, args), entries):
                print_result(result)
                results.append(result)

    with_categories = False

    if not args.no_categories:
        print("\nKategorisierung über die Investigate API...")
        token = get_token(args)

        if token:
            with_categories = categorize_all(token, results)

        if args.categories_only and not with_categories:
            sys.exit(1)

    print()

    if not args.categories_only:
        counts = {s: sum(1 for r in results if r["status"] == s) for s in STATUSES}
        print("  ".join(
            f"{s.title()}: {ts.color(str(counts[s]), STATUS_COLORS[s])}"
            for s in STATUSES
        ))

        html_path = os.path.join(args.out_dir, f"urlCheck_{stamp}.html")
        write_html(html_path, results, args.file, with_categories, started)
        print(f"\nHTML-Report: {html_path}")

    if with_categories:
        csv_path = os.path.join(args.out_dir, f"categories_{stamp}.csv")
        write_csv(csv_path, results)
        print(f"CSV:         {csv_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
        sys.exit(1)
