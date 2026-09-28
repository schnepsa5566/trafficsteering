#!/usr/bin/env python3
"""
Gleicht die reachableAddresses (Traffic Steering) einer Cisco Secure Access
Private Resource mit dem Inhalt von trafficUrls.txt ab.

- trafficUrls.txt ist der vollständige Soll-Zustand: fehlende Einträge
  werden entfernt, neue hinzugefügt.
- Idempotent: stimmt der Ist-Zustand bereits, wird kein PUT gesendet.
- Credentials kommen aus Umgebungsvariablen oder aus secrets.env.
"""

import os
import sys
import json
import argparse
import requests


BASE_URL = "https://api.sse.cisco.com"
TOKEN_URL = f"{BASE_URL}/auth/v2/token"
PRIVATE_RESOURCES_URL = f"{BASE_URL}/policies/v2/privateResources"

# ------------------------------------------------------------------
# Konfiguration
# ------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_FILE = os.path.join(SCRIPT_DIR, "secrets.env")
DEFAULT_URLS_FILE = os.path.join(SCRIPT_DIR, "trafficUrls.txt")

# ID des bestehenden Private Resource
RESOURCE_ID = 123456


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
    """Einträge vergleichbar machen (FQDNs sind case-insensitiv)."""

    return address.strip().lower()


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


def get_private_resource(token, resource_id):
    """Bestehendes Private Resource laden."""

    url = f"{PRIVATE_RESOURCES_URL}/{resource_id}"

    response = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        timeout=30,
    )

    response.raise_for_status()

    return response.json()


def find_client_access(resource):
    """Client Access Type des Private Resource suchen."""

    for access_type in resource.get("accessTypes", []):
        if access_type.get("type") == "client":
            return access_type

    return None


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


def build_update_payload(resource):
    """
    Cisco erwartet beim PUT mindestens:
      - name
      - accessTypes
      - resourceAddresses

    Read-only Felder wie resourceId, createdAt usw.
    werden daher nicht zurückgesendet.
    """

    payload = {
        "name": resource["name"],
        "accessTypes": resource["accessTypes"],
        "resourceAddresses": resource["resourceAddresses"],
    }

    # Optionale Felder übernehmen, sofern vorhanden
    optional_fields = [
        "description",
        "dnsServerId",
        "certificateId",
        "resourceGroupIds",
    ]

    for field in optional_fields:
        if field in resource and resource[field] is not None:
            payload[field] = resource[field]

    return payload


def put_private_resource(token, resource_id, payload):
    """Private Resource aktualisieren."""

    url = f"{PRIVATE_RESOURCES_URL}/{resource_id}"

    response = requests.put(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=30,
    )

    if not response.ok:
        print("\nCisco API Fehler:")
        print(f"HTTP {response.status_code}")
        print(response.text)
        response.raise_for_status()

    return response.json()


def parse_args():
    parser = argparse.ArgumentParser(
        description="reachableAddresses einer Private Resource mit "
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
        "--resource-id", type=int, default=RESOURCE_ID,
        help=f"ID des Private Resource (Default: {RESOURCE_ID})",
    )
    parser.add_argument(
        "--allow-empty", action="store_true",
        help="Leere Soll-Liste erlauben (entfernt alle Adressen)",
    )
    return parser.parse_args()


def main():

    args = parse_args()

    try:
        secrets = load_secrets(SECRETS_FILE)
        api_key = secrets.get("CISCO_SECURE_ACCESS_KEY")
        api_secret = secrets.get("CISCO_SECURE_ACCESS_SECRET")

        if not api_key or not api_secret:
            print(
                "Fehler: CISCO_SECURE_ACCESS_KEY und "
                "CISCO_SECURE_ACCESS_SECRET müssen gesetzt sein "
                "(Umgebungsvariablen oder secrets.env, "
                "siehe secrets.env.example)."
            )
            sys.exit(1)

        desired = load_desired_addresses(args.file)

        if not desired and not args.allow_empty:
            print(
                f"Fehler: {args.file} enthält keine Einträge. "
                "Das würde alle reachableAddresses entfernen. "
                "Mit --allow-empty erzwingen."
            )
            sys.exit(1)

        print("Hole OAuth Token...")
        token = get_access_token(api_key, api_secret)

        print(f"Lade Private Resource {args.resource_id}...")
        resource = get_private_resource(token, args.resource_id)

        print(f"Resource: {resource.get('name')}")

        client_access = find_client_access(resource)

        if client_access is None:
            raise RuntimeError(
                "Das Private Resource besitzt keinen "
                "'client' Access Type."
            )

        current = client_access.get("reachableAddresses") or []
        to_add, to_remove, unchanged = compute_diff(current, desired)

        print(f"\nUnverändert: {unchanged}")
        for address in to_add:
            print(f"  + {address}")
        for address in to_remove:
            print(f"  - {address}")

        if not to_add and not to_remove:
            print("\nKeine Änderungen notwendig.")
            return

        if args.dry_run:
            print("\nDry-Run: keine Änderungen durchgeführt.")
            return

        if not args.yes:
            answer = input("\nÄnderung wirklich durchführen? [y/N]: ")

            if answer.lower() not in ("y", "yes", "j", "ja"):
                print("Abgebrochen.")
                return

        client_access["reachableAddresses"] = desired
        payload = build_update_payload(resource)

        print("\nSende PUT Request...")

        result = put_private_resource(token, args.resource_id, payload)

        result_access = find_client_access(result) or {}
        reported = result_access.get("reachableAddresses") or []

        print("\nCisco meldet reachableAddresses:")
        print(json.dumps(reported, indent=2))

        to_add, to_remove, _ = compute_diff(reported, desired)

        if to_add or to_remove:
            print(
                "\nWarnung: Cisco meldet einen abweichenden Zustand "
                "(siehe oben)."
            )
            sys.exit(1)

        print("\nUpdate erfolgreich.")

    except requests.HTTPError as exc:
        print(f"\nHTTP Fehler: {exc}")
        sys.exit(1)

    except Exception as exc:
        print(f"\nFehler: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
