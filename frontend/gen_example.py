#!/usr/bin/env python3
"""
PIT Chile Looking Glass - Generador de ejemplos con tooltips
Consulta nombres de redes via RDAP (arin/lacnic) y actualiza index.html
con data-tooltip en los botones de ejemplos rapidos.

Uso:
    python gen_examples.py
    python gen_examples.py --html /ruta/al/index.html
    python gen_examples.py --dry-run   (solo muestra, no escribe)

Autor: PIT Chile NOC
"""

import argparse
import json
import re
import time
import urllib.request
import urllib.error
from pathlib import Path

# ---------------------------------------------------------------------------
# Ejemplos configurados: prefijo/ASN -> descripcion base
# Se complementa con nombre real via RDAP en tiempo de ejecucion.
# ---------------------------------------------------------------------------

EJEMPLOS = [
    # --- PIT Chile SCL ---
    {"val": "45.68.16.0/22",    "label": "PIT SCL LAN",       "tipo": "prefix", "asn": "61522"},
    {"val": "45.68.16.1",       "label": "PIT SCL RS1",        "tipo": "ip",     "asn": "61522"},
    # --- PIT Mexico ---
    {"val": "200.23.206.0/24",  "label": "PIT MX LAN",         "tipo": "prefix", "asn": "61525"},
    {"val": "200.23.206.1",     "label": "PIT MX RS1",          "tipo": "ip",     "asn": "61525"},
    # --- PIT Argentina ---
    {"val": "45.68.44.0/24",    "label": "PIT AR LAN",          "tipo": "prefix", "asn": "61523"},
    # --- PIT Peru ---
    {"val": "45.183.47.0/24",   "label": "PIT PE LAN",          "tipo": "prefix", "asn": "64115"},
    # --- Miembros PIT Chile conocidos ---
    {"val": "AS61522",          "label": "RS PIT Chile",        "tipo": "asn",    "asn": "61522"},
    {"val": "AS61525",          "label": "RS PIT Mexico",       "tipo": "asn",    "asn": "61525"},
    {"val": "AS22927",          "label": "Telefonica Chile",    "tipo": "asn",    "asn": "22927"},
    {"val": "AS7418",           "label": "Entel Chile",         "tipo": "asn",    "asn": "7418"},
    {"val": "AS14259",          "label": "GTD Chile",           "tipo": "asn",    "asn": "14259"},
    {"val": "AS6471",           "label": "Entel Chile Fijos",   "tipo": "asn",    "asn": "6471"},
    {"val": "AS13335",          "label": "Cloudflare",          "tipo": "asn",    "asn": "13335"},
    {"val": "AS20940",          "label": "Akamai",              "tipo": "asn",    "asn": "20940"},
    {"val": "AS15169",          "label": "Google",              "tipo": "asn",    "asn": "15169"},
    {"val": "AS16509",          "label": "Amazon AWS",          "tipo": "asn",    "asn": "16509"},
    {"val": "AS8075",           "label": "Microsoft",           "tipo": "asn",    "asn": "8075"},
    # --- Peru ---
    {"val": "AS6147",           "label": "Telefonica Peru",     "tipo": "asn",    "asn": "6147"},
    # --- Mexico ---
    {"val": "AS8151",           "label": "TELMEX",              "tipo": "asn",    "asn": "8151"},
    # --- Argentina ---
    {"val": "AS7303",           "label": "Telecom Argentina",   "tipo": "asn",    "asn": "7303"},
]

# ---------------------------------------------------------------------------
# RDAP lookup
# ---------------------------------------------------------------------------

RDAP_CACHE: dict[str, str] = {}


def rdap_asn_name(asn: str) -> str:
    """Retorna el nombre de la org para un ASN via RDAP. Cachea resultados."""
    asn = asn.lstrip("ASas")
    if asn in RDAP_CACHE:
        return RDAP_CACHE[asn]

    urls = [
        f"https://rdap.lacnic.net/rdap/autnum/{asn}",
        f"https://rdap.arin.net/registry/autnum/{asn}",
        f"https://rdap.db.ripe.net/autnum/{asn}",
    ]

    name = ""
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read())
            # Intentar sacar nombre de distintos campos
            name = (
                data.get("name") or
                data.get("handle") or
                (data.get("entities") or [{}])[0].get("handle", "") or
                ""
            )
            # Limpiar sufijos comunes
            name = re.sub(r"-(LACNIC|ARIN|RIPE|APNIC)$", "", name).strip()
            if name:
                break
        except Exception:
            time.sleep(0.2)
            continue

    RDAP_CACHE[asn] = name
    return name


# ---------------------------------------------------------------------------
# Generador de HTML para los botones
# ---------------------------------------------------------------------------

def build_buttons_html(ejemplos: list[dict], fetch_rdap: bool = True) -> str:
    """Genera el bloque HTML de botones quick-examples con tooltips."""
    lines = ['        <span class="qe-label">Ejemplos:</span>']

    for ej in ejemplos:
        val   = ej["val"]
        label = ej["label"]
        asn   = ej.get("asn", "")

        # Tooltip: nombre RDAP + descripcion base
        tooltip = label
        if fetch_rdap and asn:
            rdap_name = rdap_asn_name(asn)
            if rdap_name and rdap_name.upper() != label.upper():
                tooltip = f"{label} — {rdap_name} (AS{asn})"
            else:
                tooltip = f"{label} (AS{asn})"

        lines.append(
            f'        <button class="qe-btn" data-val="{val}" title="{tooltip}">'
            f'{val}</button>'
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Patch index.html
# ---------------------------------------------------------------------------

def patch_html(html_path: Path, new_buttons: str, dry_run: bool = False) -> bool:
    """Reemplaza el bloque quick-examples en index.html."""
    content = html_path.read_text(encoding="utf-8")

    # Patron que matchea todo el bloque quick-examples
    pattern = re.compile(
        r'(<div class="quick-examples"[^>]*>)\s*(.*?)\s*(</div>)',
        re.DOTALL,
    )

    if not pattern.search(content):
        print("ERROR: No se encontro el bloque quick-examples en el HTML.")
        return False

    new_block = f'<div class="quick-examples" id="quick-examples">\n{new_buttons}\n        </div>'
    new_content = pattern.sub(new_block, content)

    if dry_run:
        print("--- DRY RUN: bloque generado ---")
        print(new_buttons)
        return True

    html_path.write_text(new_content, encoding="utf-8")
    print(f"OK: {html_path} actualizado con {len(EJEMPLOS)} ejemplos.")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Genera botones de ejemplos con tooltips RDAP para PIT Chile LG"
    )
    parser.add_argument(
        "--html",
        default=str(Path(__file__).parent.parent / "frontend" / "index.html"),
        help="Ruta al index.html (default: ../frontend/index.html)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Solo muestra el HTML generado, no escribe el archivo",
    )
    parser.add_argument(
        "--no-rdap",
        action="store_true",
        help="No consultar RDAP, usar solo los labels del script",
    )
    args = parser.parse_args()

    html_path = Path(args.html)
    if not html_path.exists():
        print(f"ERROR: {html_path} no existe.")
        return

    fetch = not args.no_rdap
    if fetch:
        print(f"Consultando RDAP para {len(EJEMPLOS)} entradas...")

    buttons_html = build_buttons_html(EJEMPLOS, fetch_rdap=fetch)
    patch_html(html_path, buttons_html, dry_run=args.dry_run)

    if fetch:
        print(f"\nCache RDAP ({len(RDAP_CACHE)} ASNs):")
        for asn, name in sorted(RDAP_CACHE.items(), key=lambda x: int(x[0])):
            print(f"  AS{asn:>8} -> {name or '(sin nombre)'}")


if __name__ == "__main__":
    main()
