#!/usr/bin/env python3
"""
PIT Chile Looking Glass - Backend v2.1
Herramientas: BGP (via RouteViews API REST), Whois, RPKI, DNS, Prefix Info

Autor: PIT Chile NOC
+GitHub
"""

import asyncio
import ipaddress
import json
import logging
import re
import socket
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"

def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)

CFG = load_config()

logging.basicConfig(
    level=logging.DEBUG if CFG["server"]["debug"] else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("pit-lg")

_rate_store: dict[str, list[float]] = {}

def check_rate_limit(ip: str) -> bool:
    limit = CFG["security"]["rate_limit_per_minute"]
    now = time.time()
    hits = [t for t in _rate_store.get(ip, []) if now - t < 60]
    if len(hits) >= limit:
        return False
    hits.append(now)
    _rate_store[ip] = hits
    return True

# ---------------------------------------------------------------------------
# RouteViews API REST (HTTPS - funciona detras de cualquier proxy)
# Docs: https://api.routeviews.org/docs/
# ---------------------------------------------------------------------------

RV_API_BASE = "https://api.routeviews.org"
RV_API_KEY  = CFG.get("routeviews", {}).get("api_key", "")

# hostname telnet -> slug de la API REST
RV_COLLECTOR_MAP = {
    "pit.scl.routeviews.org":          None,
    "pitmx.qro.routeviews.org":        None,
    "route-views2.routeviews.org":     None,
    "route-views3.routeviews.org":     "route-views3",
    "route-views4.routeviews.org":     "route-views4",
    "route-views5.routeviews.org":     "route-views5",
    "route-views6.routeviews.org":     "route-views6",
    "route-views.eqix.routeviews.org": "route-views.eqix",
    "route-views.linx.routeviews.org": "route-views.linx",
    "ix-br2.gru.routeviews.org":       "ix-br2.gru",
}


NL = "\n"  # newline helper


def rv_api_get(path: str, timeout: int = 15) -> dict:
    url = f"{RV_API_BASE}{path}"
    headers = {"Accept": "application/json", "User-Agent": "PIT-Chile-LG/2.1"}
    if RV_API_KEY:
        headers["Api-Key"] = RV_API_KEY
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def format_bgp_routes(data, query: str) -> str:
    if not data:
        return '% Network not in table'
    # /asn/ endpoint retorna lista de strings (prefijos)
    if isinstance(data, list) and data and isinstance(data[0], str):
        lines = [
            'Prefijos originados por AS' + str(query),
            'Total: ' + str(len(data)) + ' prefijos',
            '-' * 50,
        ]
        for pfx in data[:300]:
            lines.append('*>  ' + str(pfx))
        if len(data) > 300:
            lines.append('... (' + str(len(data)) + ' total, mostrando 300)')
        return NL.join(lines)
    # /prefix/ endpoint retorna lista de dicts con reporting_peers
    entries = data if isinstance(data, list) else [data]
    lines = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        prefix     = entry.get('prefix', query)
        origin_asn = entry.get('origin_asn', '')
        rpki_state = entry.get('rpki_state', 'unknown')
        peers      = entry.get('reporting_peers', [])
        lines.append('BGP routing table entry for ' + str(prefix))
        lines.append('Origin ASN : ' + str(origin_asn))
        lines.append('RPKI state : ' + str(rpki_state).upper())
        lines.append('Paths      : (' + str(len(peers)) + ' reporting peers)')
        lines.append('')
        lines.append('{:<3} {:<18} {:<16} {}'.format('', 'Peer ASN', 'Peer IP', 'AS_PATH'))
        lines.append('-' * 70)
        for i, peer in enumerate(peers[:50]):
            best = '*>' if i == 0 else '* '
            lines.append('{:<3} {:<18} {:<16} {}'.format(
                best, str(peer.get('peer_asn','')), str(peer.get('peer_addr','')), str(peer.get('as_path',''))))
            comms = str(peer.get('communities', ''))
            if comms:
                lines.append('    Community: ' + comms)
        if len(peers) > 50:
            lines.append('... (' + str(len(peers)) + ' peers total, mostrando 50)')
        roas = entry.get('rpki_roas', [])
        if roas:
            lines.append('')
            lines.append('ROAs:')
            for roa in roas:
                lines.append('  ' + str(roa.get('prefix','')) +
                              ' max/' + str(roa.get('max_length','')) +
                              ' AS' + str(roa.get('asn','')) +
                              ' TA:' + str(roa.get('ta','')))
    return NL.join(lines) if lines else '% Network not in table'


def format_bgp_summary(data: dict) -> str:
    lines = [
        "BGP router identifier 0.0.0.0",
        "{:<18} {:>3} {:>8} {:>14}".format("Neighbor", "V", "AS", "State/PfxRcd"),
        "-" * 60,
    ]
    peers = data.get("data", {})
    if isinstance(peers, list):
        for p in peers:
            neighbor = str(p.get("peer_ip", ""))
            asn      = str(p.get("peer_asn", ""))
            pfx      = str(p.get("prefix_count", p.get("routes", "?")))
            lines.append("{:<18} {:>3} {:>8} {:>14}".format(neighbor, "4", asn, pfx))
    return "\n".join(lines)


async def bgp_query_api(rs: dict, command_key: str, query: str) -> str:
    host      = rs["host"]
    collector = RV_COLLECTOR_MAP.get(host)
    timeout   = CFG["security"]["telnet_timeout"]

    if collector is None:
        cmd = build_command(rs, command_key, query)
        log.debug("Telnet fallback: %s cmd=%r", host, cmd)
        return await telnet_query(
            host=host, port=rs.get("port", 23),
            commands=[cmd], prompt=rs.get("prompt", ">"),
            timeout=timeout)

    try:
        if command_key in ("bgp_route", "bgp_route_v6"):
            pfx  = urllib.parse.quote(query, safe="")
            data = await asyncio.to_thread(rv_api_get,
                "/prefix/" + pfx + "?collector=" + collector, timeout)
            return format_bgp_routes(data, query)

        elif command_key == "bgp_aspath":
            data = await asyncio.to_thread(rv_api_get,
                "/asn/" + query + "?collector=" + collector, timeout)
            return format_bgp_routes(data, query)

        elif command_key in ("bgp_summary", "bgp_summary_v6"):
            data = await asyncio.to_thread(rv_api_get,
                "/rib/peers?collector=" + collector, timeout)
            return format_bgp_summary(data)

        else:
            return (
                "% Comando '" + command_key + "' no disponible via API REST.\n"
                "% Use un route server con acceso telnet directo."
            )

    except Exception as e:
        return "% Error consultando RouteViews API: " + str(e) + "\n% Intente con otro route server."


async def telnet_query(host: str, port: int, commands: list,
                       prompt: str, timeout: int) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except asyncio.TimeoutError:
        raise RuntimeError("Timeout conectando a " + host + ":" + str(port))
    except Exception as e:
        raise RuntimeError("Error conectando a " + host + ":" + str(port) + ": " + str(e))

    parts = []

    async def read_until_prompt(p: str, t: int) -> str:
        buf = b""
        deadline = asyncio.get_event_loop().time() + t
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=min(remaining, 2.0))
                if not chunk:
                    break
                buf += chunk
                if p.encode() in buf:
                    break
            except asyncio.TimeoutError:
                break
        return buf.decode("utf-8", errors="replace")

    try:
        await read_until_prompt(prompt, timeout)
        for cmd in commands:
            writer.write((cmd + "\n").encode())
            await writer.drain()
            parts.append(await read_until_prompt(prompt, timeout))
        writer.write(b"exit\n")
        await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    raw = "\n".join(parts)
    raw = re.sub(r'\x1b\[[0-9;]*[mKHJ]', '', raw)
    raw = re.sub(r'\r', '', raw)

    if raw.strip().startswith("HTTP/") and "400" in raw[:50]:
        raise RuntimeError(
            "Proxy HTTP interceptando conexion telnet a " + host + ":" + str(port) + ". "
            "Seleccione un route server que use API REST (rv3, rv4, rv5, rv6, eqix, linx)."
        )

    lines = raw.splitlines()
    max_lines = CFG["security"]["max_output_lines"]
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["... (truncado a " + str(max_lines) + " lineas)"]
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Herramientas directas
# ---------------------------------------------------------------------------

def run_whois(query: str) -> str:
    query = query.strip()
    server = "whois.lacnic.net"
    try:
        ip = ipaddress.ip_address(query.split("/")[0])
        first = int(str(ip).split(".")[0]) if ip.version == 4 else 0
        if first in range(1, 10) or first in range(100, 126):
            server = "whois.arin.net"
        elif first >= 193:
            server = "whois.ripe.net"
    except ValueError:
        if query.upper().startswith("AS"):
            asn = int(re.sub(r'[^0-9]', '', query))
            server = "whois.arin.net" if asn < 27648 else "whois.lacnic.net"
        else:
            server = "whois.iana.org"
    try:
        s = socket.create_connection((server, 43), timeout=12)
        s.sendall((query + "\r\n").encode())
        result = b""
        s.settimeout(10)
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            result += chunk
        s.close()
        output = result.decode("utf-8", errors="replace")
        return "% Whois server: " + server + "\n% Query      : " + query + "\n" + "=" * 60 + "\n" + output
    except Exception as e:
        raise RuntimeError("Error en whois (" + server + "): " + str(e))


def fetch_rdap(query: str) -> dict:
    query = query.strip()
    is_asn = query.upper().startswith("AS")
    if is_asn:
        asn = re.sub(r'[^0-9]', '', query)
        urls = [
            "https://rdap.lacnic.net/rdap/autnum/" + asn,
            "https://rdap.arin.net/registry/autnum/" + asn,
            "https://rdap.db.ripe.net/autnum/" + asn,
        ]
    else:
        target = query.split("/")[0]
        urls = [
            "https://rdap.lacnic.net/rdap/ip/" + target,
            "https://rdap.arin.net/registry/ip/" + target,
            "https://rdap.db.ripe.net/ip/" + target,
        ]
    last_err = ""
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={
                "Accept": "application/json",
                "User-Agent": "PIT-Chile-LG/2.1"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                return json.loads(resp.read())
        except Exception as e:
            last_err = str(e)
            continue
    raise RuntimeError("RDAP no disponible: " + last_err)


def fetch_rpki(prefix: str, asn: str = "") -> dict:
    asn_clean = re.sub(r'[^0-9]', '', asn) if asn else ""
    prefix_enc = urllib.parse.quote(prefix, safe="")
    urls_to_try = []
    if asn_clean:
        urls_to_try.append(
            "https://stat.ripe.net/data/rpki-validation/data.json"
            "?resource=" + asn_clean + "&prefix=" + prefix_enc
        )
    urls_to_try.append(
        "https://stat.ripe.net/data/rpki-validation/data.json"
        "?resource=0&prefix=" + prefix_enc
    )
    last_err = ""
    for url in urls_to_try:
        try:
            req = urllib.request.Request(url, headers={
                "Accept": "application/json",
                "User-Agent": "PIT-Chile-LG/2.1"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read())
                if "data" in data:
                    d     = data["data"]
                    state = d.get("status", "unknown")
                    roas  = d.get("validating_roas", [])
                    return {
                        "state":           state,
                        "prefix":          prefix,
                        "asn":             asn_clean or "any",
                        "source":          "RIPEstat",
                        "validating_roas": roas,
                    }
        except Exception as e:
            last_err = str(e)
            continue
    raise RuntimeError("RPKI no disponible: " + last_err)


def dns_lookup(query: str) -> str:
    query = query.strip()
    lines = ["DNS Lookup : " + query, "=" * 50]
    try:
        ip = ipaddress.ip_address(query)
        try:
            ptr = socket.gethostbyaddr(str(ip))
            lines.append("PTR   : " + ptr[0])
            for alias in ptr[1]:
                lines.append("ALIAS : " + alias)
        except socket.herror:
            lines.append("PTR   : (sin registro PTR)")
    except ValueError:
        try:
            infos = socket.getaddrinfo(query, None)
            seen = set()
            for info in infos:
                addr = info[4][0]
                if addr not in seen:
                    seen.add(addr)
                    family = "AAAA  " if info[0] == socket.AF_INET6 else "A     "
                    lines.append(family + ": " + addr)
            lines.append("")
            for addr in seen:
                try:
                    ptr = socket.gethostbyaddr(addr)
                    lines.append("PTR   : " + addr + " -> " + ptr[0])
                except Exception:
                    pass
        except socket.gaierror as e:
            lines.append("ERROR : " + str(e))
    return "\n".join(lines)


def prefix_info(prefix: str) -> str:
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        hosts_list = list(net.hosts()) if net.num_addresses <= 512 else []
        lines = [
            "Prefix    : " + str(net),
            "Version   : IPv" + str(net.version),
        ]
        if net.version == 4:
            lines += [
                "Netmask   : " + str(net.netmask),
                "Wildcard  : " + str(net.hostmask),
            ]
        lines.append("Network   : " + str(net.network_address))
        if net.version == 4:
            lines.append("Broadcast : " + str(net.broadcast_address))
        if hosts_list:
            lines += [
                "First host: " + str(hosts_list[0]),
                "Last host : " + str(hosts_list[-1]),
            ]
        usable = net.num_addresses - 2 if net.version == 4 and net.prefixlen < 31 else net.num_addresses
        lines += [
            "Hosts     : " + "{:,}".format(usable),
            "Is private: " + str(net.is_private),
            "Is global : " + str(net.is_global),
        ]
        if net.prefixlen > 8:
            lines.append("Supernet  : " + str(net.supernet()))
        if net.version == 4 and net.prefixlen < 24:
            count = 2 ** (24 - net.prefixlen)
            lines.append("Subnets/24: " + "{:,}".format(count))
        return "\n".join(lines)
    except ValueError as e:
        raise RuntimeError("Prefijo invalido: " + str(e))

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title=CFG["server"]["title"],
    description=CFG["server"]["description"],
    version=CFG.get("server", {}).get("version", "2.1.0"),
    docs_url=None,
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["GET", "POST"], allow_headers=["*"])

STATIC_DIR = Path(__file__).parent.parent / "frontend" / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/api/docs", response_class=HTMLResponse, include_in_schema=False)
async def custom_swagger():
    version = CFG.get("server", {}).get("version", "2.1.0")
    html = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PIT Chile Looking Glass — API Docs</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --orange: #F37021;
      --orange-dark: #c45a00;
      --orange-light: #fef3eb;
      --blue: #378ADD;
      --dark: #1a1a1a;
      --text: #222;
      --muted: #666;
      --border: #e0e0e0;
      --bg: #f5f5f5;
      --card: #fff;
      --radius: 6px;
      --mono: 'JetBrains Mono', monospace;
      --sans: 'Inter', sans-serif;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: var(--sans); background: var(--bg); color: var(--text); line-height: 1.6; }

    /* HEADER */
    .site-header {
      background: var(--dark);
      border-bottom: 3px solid var(--orange);
      position: sticky; top: 0; z-index: 100;
    }
    .header-inner {
      max-width: 1100px; margin: 0 auto;
      display: flex; align-items: center; gap: 16px;
      padding: 0 24px; height: 56px;
    }
    .brand-logo { height: 34px; border-radius: 3px; }
    .brand-name { color: #fff; font-size: 15px; font-weight: 600; }
    .brand-name span { color: var(--orange); }
    .header-nav { display: flex; gap: 4px; margin-left: auto; }
    .header-nav a {
      color: #aaa; text-decoration: none; font-size: 12px;
      padding: 5px 12px; border-radius: 4px; transition: all .15s;
    }
    .header-nav a:hover { color: #fff; background: #333; }
    .header-nav a.active { color: var(--orange); font-weight: 500; }
    .api-badge {
      background: var(--orange); color: #fff;
      font-size: 11px; font-weight: 700;
      padding: 3px 10px; border-radius: 3px; letter-spacing: .5px;
    }

    /* HERO */
    .hero {
      background: var(--dark);
      border-bottom: 1px solid #2a2a2a;
      padding: 32px 24px;
    }
    .hero-inner { max-width: 1100px; margin: 0 auto; }
    .hero h1 { color: #fff; font-size: 26px; font-weight: 700; margin-bottom: 6px; }
    .hero h1 span { color: var(--orange); }
    .hero p { color: #aaa; font-size: 14px; max-width: 600px; }
    .hero-meta {
      display: flex; gap: 20px; margin-top: 16px; flex-wrap: wrap;
    }
    .hero-meta-item { font-family: var(--mono); font-size: 12px; color: #777; }
    .hero-meta-item strong { color: var(--orange); margin-right: 4px; }

    /* MAIN */
    .main { max-width: 1100px; margin: 32px auto; padding: 0 24px 60px; }
    .section-title {
      font-size: 11px; font-weight: 700; letter-spacing: 1.5px;
      text-transform: uppercase; color: var(--muted);
      margin: 32px 0 12px; padding-bottom: 8px;
      border-bottom: 2px solid var(--orange);
      display: flex; align-items: center; gap: 8px;
    }

    /* ENDPOINT CARD */
    .endpoint {
      background: var(--card); border: 1px solid var(--border);
      border-radius: var(--radius); margin-bottom: 8px;
      overflow: hidden; transition: box-shadow .15s;
    }
    .endpoint:hover { box-shadow: 0 2px 12px rgba(0,0,0,.08); }
    .endpoint-header {
      display: flex; align-items: center; gap: 14px;
      padding: 14px 18px; cursor: pointer;
      user-select: none;
    }
    .method {
      font-family: var(--mono); font-size: 11px; font-weight: 700;
      padding: 3px 10px; border-radius: 3px; min-width: 52px;
      text-align: center; letter-spacing: .5px;
    }
    .method.get  { background: var(--blue);   color: #fff; }
    .method.post { background: var(--orange); color: #fff; }
    .ep-path {
      font-family: var(--mono); font-size: 13px; font-weight: 500; color: var(--text);
    }
    .ep-path .param { color: var(--orange); }
    .ep-desc { font-size: 12px; color: var(--muted); margin-left: auto; }
    .ep-arrow { color: var(--muted); font-size: 12px; margin-left: 8px; transition: transform .2s; }
    .endpoint.open .ep-arrow { transform: rotate(180deg); }

    .endpoint-body {
      display: none; border-top: 1px solid var(--border);
      background: #fafafa; padding: 18px 20px;
    }
    .endpoint.open .endpoint-body { display: block; }

    .ep-section { margin-bottom: 14px; }
    .ep-section-label {
      font-size: 10px; font-weight: 700; letter-spacing: 1px;
      text-transform: uppercase; color: var(--muted); margin-bottom: 6px;
    }
    .ep-full-desc { font-size: 13px; color: #444; }

    /* Request body */
    .code-block {
      background: #1e1e1e; color: #d4d4d4;
      font-family: var(--mono); font-size: 12px; line-height: 1.7;
      padding: 14px 16px; border-radius: 4px;
      overflow-x: auto; white-space: pre;
    }
    .code-block .key   { color: #9cdcfe; }
    .code-block .str   { color: #ce9178; }
    .code-block .kw    { color: #569cd6; }
    .code-block .num   { color: #b5cea8; }
    .code-block .cmt   { color: #6a9955; }

    /* Response badges */
    .response-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 6px; }
    .resp-badge {
      font-family: var(--mono); font-size: 11px; font-weight: 600;
      padding: 3px 10px; border-radius: 3px;
    }
    .resp-badge.ok  { background: #e8f5e9; color: #2e7d32; }
    .resp-badge.err { background: #ffebee; color: #c62828; }

    /* Try it */
    .try-section {
      background: #fff; border: 1px solid var(--border);
      border-radius: 4px; padding: 14px 16px; margin-top: 12px;
    }
    .try-label { font-size: 11px; font-weight: 700; color: var(--orange); letter-spacing: .5px; margin-bottom: 10px; }
    .try-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
    .try-input {
      flex: 1; min-width: 200px;
      font-family: var(--mono); font-size: 12px;
      border: 1px solid var(--border); border-radius: 4px;
      padding: 7px 10px; outline: none;
      transition: border-color .15s;
    }
    .try-input:focus { border-color: var(--orange); box-shadow: 0 0 0 2px rgba(243,112,33,.15); }
    .try-btn {
      background: var(--orange); color: #fff;
      border: none; border-radius: 4px;
      padding: 7px 18px; font-size: 12px; font-weight: 600;
      cursor: pointer; font-family: var(--sans); transition: background .15s;
    }
    .try-btn:hover { background: var(--orange-dark); }
    .try-result {
      display: none; margin-top: 10px;
      background: #1e1e1e; color: #d4d4d4;
      font-family: var(--mono); font-size: 12px; line-height: 1.6;
      padding: 12px 14px; border-radius: 4px;
      white-space: pre-wrap; word-break: break-all;
      max-height: 300px; overflow: auto;
    }
    .try-result.show { display: block; }
    .try-status { font-size: 11px; color: var(--muted); margin-top: 6px; font-family: var(--mono); }

    /* FOOTER */
    .site-footer {
      background: var(--dark); border-top: 3px solid var(--orange);
      padding: 20px 24px; text-align: center;
      font-size: 11px; color: #666; font-family: var(--mono);
    }
    .site-footer a { color: var(--orange); text-decoration: none; }
  </style>
</head>
<body>

<header class="site-header">
  <div class="header-inner">
    <img src="https://www.pitchile.cl/wp/wp-content/uploads/2025/09/PitHubLatinoamerica.jpg"
         alt="PIT Chile" class="brand-logo" onerror="this.style.display='none'">
    <div class="brand-name">PIT Chile <span>Looking Glass</span></div>
    <nav class="header-nav">
      <a href="/">Interface</a>
      <a href="/api/docs" class="active">API Docs</a>
      <a href="/api/openapi.json">OpenAPI JSON</a>
      <a href="https://www.pitchile.cl" target="_blank">pitchile.cl</a>
    </nav>
    <span class="api-badge">API v__VERSION__</span>
  </div>
</header>

<div class="hero">
  <div class="hero-inner">
    <h1>PIT Chile <span>Looking Glass</span> — API REST</h1>
    <p>Herramientas de diagnostico de red LATAM. BGP via RouteViews API, Whois, RPKI, DNS y Prefix Info.</p>
    <div class="hero-meta">
      <div class="hero-meta-item"><strong>Base URL</strong>/api</div>
      <div class="hero-meta-item"><strong>Version</strong>v__VERSION__</div>
      <div class="hero-meta-item"><strong>Formato</strong>JSON</div>
      <div class="hero-meta-item"><strong>Auth</strong>Sin autenticacion</div>
      <div class="hero-meta-item"><strong>NOC</strong>noc@pitchile.cl</div>
    </div>
  </div>
</div>

<main class="main">

  <div class="section-title">Configuracion y Estado</div>

  <div class="endpoint" id="ep-health">
    <div class="endpoint-header" onclick="toggle('ep-health')">
      <span class="method get">GET</span>
      <span class="ep-path">/api/health</span>
      <span class="ep-desc">Health check del servicio</span>
      <span class="ep-arrow">&#9660;</span>
    </div>
    <div class="endpoint-body">
      <div class="ep-section">
        <div class="ep-section-label">Descripcion</div>
        <div class="ep-full-desc">Verifica que el servicio esta corriendo. Retorna version y titulo del LG.</div>
      </div>
      <div class="ep-section">
        <div class="ep-section-label">Respuesta 200</div>
        <div class="code-block"><span class="kw">{</span>
  <span class="key">"status"</span>: <span class="str">"ok"</span>,
  <span class="key">"service"</span>: <span class="str">"PIT Chile Looking Glass"</span>,
  <span class="key">"version"</span>: <span class="str">"2.1.0"</span>
<span class="kw">}</span></div>
      </div>
      <div class="try-section">
        <div class="try-label">PROBAR</div>
        <div class="try-row">
          <button class="try-btn" onclick="tryIt('ep-health', 'GET', '/api/health')">Ejecutar GET</button>
        </div>
        <div class="try-result" id="ep-health-result"></div>
        <div class="try-status" id="ep-health-status"></div>
      </div>
    </div>
  </div>

  <div class="endpoint" id="ep-config">
    <div class="endpoint-header" onclick="toggle('ep-config')">
      <span class="method get">GET</span>
      <span class="ep-path">/api/config</span>
      <span class="ep-desc">Configuracion publica del LG</span>
      <span class="ep-arrow">&#9660;</span>
    </div>
    <div class="endpoint-body">
      <div class="ep-section">
        <div class="ep-section-label">Descripcion</div>
        <div class="ep-full-desc">Retorna la configuracion publica: route servers habilitados, comandos disponibles y feature flags. Usada por el frontend para inicializarse.</div>
      </div>
      <div class="try-section">
        <div class="try-label">PROBAR</div>
        <div class="try-row">
          <button class="try-btn" onclick="tryIt('ep-config', 'GET', '/api/config')">Ejecutar GET</button>
        </div>
        <div class="try-result" id="ep-config-result"></div>
        <div class="try-status" id="ep-config-status"></div>
      </div>
    </div>
  </div>

  <div class="section-title">BGP</div>

  <div class="endpoint" id="ep-query">
    <div class="endpoint-header" onclick="toggle('ep-query')">
      <span class="method post">POST</span>
      <span class="ep-path">/api/query</span>
      <span class="ep-desc">Query BGP en un route server</span>
      <span class="ep-arrow">&#9660;</span>
    </div>
    <div class="endpoint-body">
      <div class="ep-section">
        <div class="ep-section-label">Descripcion</div>
        <div class="ep-full-desc">Ejecuta un comando BGP en el route server seleccionado. Usa RouteViews API REST (HTTPS). Comandos disponibles: bgp_route, bgp_route_v6, bgp_aspath, bgp_summary, ping, traceroute.</div>
      </div>
      <div class="ep-section">
        <div class="ep-section-label">Request Body</div>
        <div class="code-block"><span class="kw">{</span>
  <span class="key">"route_server_id"</span>: <span class="str">"rv4"</span>,        <span class="cmt">// ID del route server</span>
  <span class="key">"command"</span>:         <span class="str">"bgp_route"</span>,  <span class="cmt">// Comando a ejecutar</span>
  <span class="key">"query"</span>:          <span class="str">"1.1.1.0/24"</span>  <span class="cmt">// Prefijo, ASN o IP</span>
<span class="kw">}</span></div>
      </div>
      <div class="ep-section">
        <div class="ep-section-label">Respuestas</div>
        <div class="response-list">
          <span class="resp-badge ok">200 OK — output del comando</span>
          <span class="resp-badge err">400 Query invalido</span>
          <span class="resp-badge err">429 Rate limit excedido</span>
          <span class="resp-badge err">503 Error conectando al route server</span>
        </div>
      </div>
      <div class="try-section">
        <div class="try-label">PROBAR</div>
        <div class="try-row">
          <input class="try-input" id="ep-query-rs" placeholder="route_server_id: rv4" value="rv4">
          <input class="try-input" id="ep-query-cmd" placeholder="command: bgp_route" value="bgp_route">
          <input class="try-input" id="ep-query-q" placeholder="query: 1.1.1.0/24" value="1.1.1.0/24">
        </div>
        <button class="try-btn" onclick="tryBGP()">Ejecutar POST</button>
        <div class="try-result" id="ep-query-result"></div>
        <div class="try-status" id="ep-query-status"></div>
      </div>
    </div>
  </div>

  <div class="section-title">Herramientas</div>

  <div class="endpoint" id="ep-tool">
    <div class="endpoint-header" onclick="toggle('ep-tool')">
      <span class="method post">POST</span>
      <span class="ep-path">/api/tool</span>
      <span class="ep-desc">Whois, RPKI, DNS, Prefix Info</span>
      <span class="ep-arrow">&#9660;</span>
    </div>
    <div class="endpoint-body">
      <div class="ep-section">
        <div class="ep-section-label">Descripcion</div>
        <div class="ep-full-desc">Ejecuta herramientas de red. Tool disponibles: whois, rpki (requiere prefijo/mascara), dns, prefix_info.</div>
      </div>
      <div class="ep-section">
        <div class="ep-section-label">Request Body</div>
        <div class="code-block"><span class="kw">{</span>
  <span class="key">"tool"</span>:  <span class="str">"whois"</span>,    <span class="cmt">// whois | rpki | dns | prefix_info</span>
  <span class="key">"query"</span>: <span class="str">"AS61522"</span>,  <span class="cmt">// IP, prefijo o ASN</span>
  <span class="key">"asn"</span>:   <span class="str">""</span>          <span class="cmt">// opcional, solo para rpki</span>
<span class="kw">}</span></div>
      </div>
      <div class="try-section">
        <div class="try-label">PROBAR</div>
        <div class="try-row">
          <input class="try-input" id="ep-tool-tool" placeholder="tool: whois" value="whois">
          <input class="try-input" id="ep-tool-q" placeholder="query: AS61522" value="AS61522">
        </div>
        <button class="try-btn" onclick="tryTool()">Ejecutar POST</button>
        <div class="try-result" id="ep-tool-result"></div>
        <div class="try-status" id="ep-tool-status"></div>
      </div>
    </div>
  </div>

  <div class="endpoint" id="ep-asn">
    <div class="endpoint-header" onclick="toggle('ep-asn')">
      <span class="method get">GET</span>
      <span class="ep-path">/api/asn/<span class="param">{asn}</span></span>
      <span class="ep-desc">Nombre de red via RDAP</span>
      <span class="ep-arrow">&#9660;</span>
    </div>
    <div class="endpoint-body">
      <div class="ep-section">
        <div class="ep-section-label">Descripcion</div>
        <div class="ep-full-desc">Retorna el nombre de una red dado su ASN via RDAP (LACNIC/ARIN/RIPE). Usado por el frontend para mostrar nombres en los ejemplos.</div>
      </div>
      <div class="try-section">
        <div class="try-label">PROBAR</div>
        <div class="try-row">
          <input class="try-input" id="ep-asn-v" placeholder="ASN: 61522" value="61522">
          <button class="try-btn" onclick="tryASN()">Ejecutar GET</button>
        </div>
        <div class="try-result" id="ep-asn-result"></div>
        <div class="try-status" id="ep-asn-status"></div>
      </div>
    </div>
  </div>

  <div class="section-title">Estado y Datos</div>

  <div class="endpoint" id="ep-servers">
    <div class="endpoint-header" onclick="toggle('ep-servers')">
      <span class="method get">GET</span>
      <span class="ep-path">/api/servers</span>
      <span class="ep-desc">Lista de route servers</span>
      <span class="ep-arrow">&#9660;</span>
    </div>
    <div class="endpoint-body">
      <div class="try-section">
        <div class="try-label">PROBAR</div>
        <button class="try-btn" onclick="tryIt('ep-servers', 'GET', '/api/servers')">Ejecutar GET</button>
        <div class="try-result" id="ep-servers-result"></div>
        <div class="try-status" id="ep-servers-status"></div>
      </div>
    </div>
  </div>

  <div class="endpoint" id="ep-cloud">
    <div class="endpoint-header" onclick="toggle('ep-cloud')">
      <span class="method get">GET</span>
      <span class="ep-path">/api/cloud-status</span>
      <span class="ep-desc">Status de cloud providers</span>
      <span class="ep-arrow">&#9660;</span>
    </div>
    <div class="endpoint-body">
      <div class="ep-section">
        <div class="ep-section-label">Descripcion</div>
        <div class="ep-full-desc">Estado en tiempo real de Azure, GCP, Oracle, AWS, Cloudflare, Akamai. Cache de 2 minutos configurable en config.yaml.</div>
      </div>
      <div class="try-section">
        <div class="try-label">PROBAR</div>
        <button class="try-btn" onclick="tryIt('ep-cloud', 'GET', '/api/cloud-status')">Ejecutar GET</button>
        <div class="try-result" id="ep-cloud-result"></div>
        <div class="try-status" id="ep-cloud-status"></div>
      </div>
    </div>
  </div>

</main>

<footer class="site-footer">
  PIT Chile Looking Glass &mdash; API REST v__VERSION__ &bull;
  <a href="https://www.pitchile.cl">pitchile.cl</a> &bull;
  <a href="mailto:noc@pitchile.cl">noc@pitchile.cl</a> &bull;
  <a href="/api/openapi.json">OpenAPI JSON</a>
</footer>

<script>
function toggle(id) {
  const el = document.getElementById(id);
  el.classList.toggle('open');
}

function fmt(data) {
  try { return JSON.stringify(JSON.parse(typeof data === 'string' ? data : JSON.stringify(data)), null, 2); }
  catch(e) { return String(data); }
}

function showResult(id, status, data) {
  const r = document.getElementById(id + '-result');
  const s = document.getElementById(id + '-status');
  if (r) { r.textContent = fmt(data); r.classList.add('show'); }
  if (s) { s.textContent = 'HTTP ' + status + ' — ' + new Date().toLocaleTimeString('es-CL'); }
}

async function tryIt(id, method, path) {
  try {
    const r = await fetch(path, { method });
    const d = await r.json();
    showResult(id, r.status, d);
  } catch(e) { showResult(id, 'ERR', e.message); }
}

async function tryBGP() {
  const body = {
    route_server_id: document.getElementById('ep-query-rs').value.trim() || 'rv4',
    command:         document.getElementById('ep-query-cmd').value.trim() || 'bgp_route',
    query:           document.getElementById('ep-query-q').value.trim()  || '1.1.1.0/24',
  };
  try {
    const r = await fetch('/api/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    showResult('ep-query', r.status, d);
  } catch(e) { showResult('ep-query', 'ERR', e.message); }
}

async function tryTool() {
  const body = {
    tool:  document.getElementById('ep-tool-tool').value.trim() || 'whois',
    query: document.getElementById('ep-tool-q').value.trim()   || 'AS61522',
    asn:   '',
  };
  try {
    const r = await fetch('/api/tool', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    showResult('ep-tool', r.status, d);
  } catch(e) { showResult('ep-tool', 'ERR', e.message); }
}

async function tryASN() {
  const asn = document.getElementById('ep-asn-v').value.trim() || '61522';
  try {
    const r = await fetch('/api/asn/' + asn);
    const d = await r.json();
    showResult('ep-asn', r.status, d);
  } catch(e) { showResult('ep-asn', 'ERR', e.message); }
}
</script>
</body>
</html>"""
    html = html.replace("__VERSION__", version)
    return HTMLResponse(html)

def get_rs(rs_id: str) -> dict:
    for rs in CFG["route_servers"]:
        if rs["id"] == rs_id and rs.get("enabled", True):
            return rs
    raise HTTPException(status_code=404, detail="Route server '" + rs_id + "' no encontrado")


def build_command(rs: dict, command_key: str, query: str) -> str:
    cmds = CFG["commands"]
    if command_key not in cmds:
        raise HTTPException(status_code=400, detail="Comando '" + command_key + "' no existe")
    cmd_cfg = cmds[command_key]
    rs_type = rs.get("type", "frr")
    cmd_template = cmd_cfg.get(rs_type) or cmd_cfg.get("frr")
    if not cmd_template:
        raise HTTPException(status_code=400, detail="Comando no soportado para tipo '" + rs_type + "'")
    return cmd_template.replace("{query}", query.strip())


def validate_query(query: str):
    max_len = CFG["security"]["max_query_length"]
    if len(query) > max_len:
        raise HTTPException(status_code=400, detail="Query demasiado largo (max " + str(max_len) + ")")
    pattern = CFG["security"]["allowed_query_regex"]
    if not re.match(pattern, query):
        raise HTTPException(status_code=400, detail="Query contiene caracteres no permitidos")


class BGPQueryRequest(BaseModel):
    route_server_id: str
    command: str
    query: Optional[str] = ""


class ToolRequest(BaseModel):
    tool: str
    query: str
    asn: Optional[str] = ""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse((Path(__file__).parent.parent / "frontend" / "index.html").read_text())


@app.get("/api/config")
async def api_config():
    servers = [
        {"id": rs["id"], "name": rs["name"], "group": rs["group"],
         "note": rs.get("note", ""), "type": rs.get("type", "frr")}
        for rs in CFG["route_servers"] if rs.get("enabled", True)
    ]
    commands = {
        k: {"label": v["label"], "description": v["description"],
            "input_placeholder": v.get("input_placeholder", ""),
            "input_label": v.get("input_label", ""),
            "no_input": v.get("no_input", False)}
        for k, v in CFG["commands"].items()
    }
    return {
        "title":         CFG["server"]["title"],
        "description":   CFG["server"]["description"],
        "contact":       CFG["server"]["contact_email"],
        "footer":        CFG["server"]["footer_text"],
        "ui":            CFG["ui"],
        "route_servers": servers,
        "commands":      commands,
        "features":      CFG.get("features", {
            "show_github":        True,
            "show_latam_ranking": True,
            "show_cloud_status":  True,
            "github_url":         "https://github.com/pitchile/looking-glass",
        }),
    }


@app.post("/api/query")
async def api_bgp_query(req: BGPQueryRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit excedido.")
    rs = get_rs(req.route_server_id)
    if req.query:
        validate_query(req.query)
    cmd = build_command(rs, req.command, req.query or "")
    log.info("[%s] BGP RS=%s CMD=%s Q=%r", client_ip, req.route_server_id, req.command, req.query)
    ts = datetime.utcnow().isoformat() + "Z"
    t0 = time.monotonic()
    try:
        output = await bgp_query_api(rs, req.command, req.query or "")
        return {"ok": True, "route_server": rs["name"], "host": rs["host"],
                "command": cmd, "output": output,
                "timestamp": ts, "elapsed_s": round(time.monotonic() - t0, 2)}
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.post("/api/tool")
async def api_tool(req: ToolRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit excedido.")
    query = req.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query vacio")
    validate_query(query)
    log.info("[%s] TOOL=%s Q=%r", client_ip, req.tool, query)
    ts = datetime.utcnow().isoformat() + "Z"
    t0 = time.monotonic()

    try:
        if req.tool == "whois":
            output = await asyncio.to_thread(run_whois, query)
            return {"ok": True, "tool": "whois", "query": query,
                    "output": output, "timestamp": ts,
                    "elapsed_s": round(time.monotonic() - t0, 2)}

        elif req.tool == "rdap":
            data = await asyncio.to_thread(fetch_rdap, query)
            lines = ["RDAP: " + query, "=" * 50,
                     "Handle  : " + data.get("handle", "-"),
                     "Name    : " + data.get("name", "-"),
                     "Type    : " + data.get("objectClassName", "-")]
            if "startAddress" in data:
                lines += ["Start   : " + data["startAddress"],
                          "End     : " + data["endAddress"]]
            for e in data.get("entities", []):
                roles = ", ".join(e.get("roles", []))
                vcard = e.get("vcardArray", [None, []])[1] if e.get("vcardArray") else []
                name = next((v[3] for v in vcard if v[0] == "fn"), e.get("handle", ""))
                lines.append("Entity  : " + name + " (" + roles + ")")
            lines += ["", json.dumps(data, indent=2, ensure_ascii=False)]
            return {"ok": True, "tool": "rdap", "query": query,
                    "output": "\n".join(lines), "data": data, "timestamp": ts,
                    "elapsed_s": round(time.monotonic() - t0, 2)}

        elif req.tool == "rpki":
            if "/" not in query:
                raise HTTPException(status_code=400,
                    detail="RPKI requiere prefijo con mascara. Ej: 45.68.16.0/22")
            data = await asyncio.to_thread(fetch_rpki, query, req.asn or "")
            state = data.get("state", "unknown")
            lines = [
                "RPKI Validation : " + query,
                "ASN             : AS" + str(req.asn) if req.asn else "",
                "Source          : " + data.get("source", "RIPEstat"),
                "=" * 50,
                "Estado          : " + state.upper(),
            ]
            for roa in data.get("validating_roas", []):
                lines.append("ROA  : " + str(roa.get("prefix", "")) +
                              " max/" + str(roa.get("max_length", "")) +
                              " AS" + str(roa.get("asn", "")))
            lines += ["", json.dumps(data, indent=2, ensure_ascii=False)]
            return {"ok": True, "tool": "rpki", "query": query,
                    "output": "\n".join(l for l in lines if l is not None),
                    "state": state, "timestamp": ts,
                    "elapsed_s": round(time.monotonic() - t0, 2)}

        elif req.tool == "dns":
            output = await asyncio.to_thread(dns_lookup, query)
            return {"ok": True, "tool": "dns", "query": query,
                    "output": output, "timestamp": ts,
                    "elapsed_s": round(time.monotonic() - t0, 2)}

        elif req.tool == "prefix_info":
            output = await asyncio.to_thread(prefix_info, query)
            return {"ok": True, "tool": "prefix_info", "query": query,
                    "output": output, "timestamp": ts,
                    "elapsed_s": round(time.monotonic() - t0, 2)}

        else:
            raise HTTPException(status_code=400, detail="Herramienta '" + req.tool + "' no existe")

    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/api/asn/{asn}")
async def api_asn_info(asn: str):
    try:
        data = await asyncio.to_thread(fetch_rdap, "AS" + asn)
        return {"asn": asn, "name": data.get("name", ""), "ok": True}
    except Exception as e:
        return {"asn": asn, "name": "", "ok": False, "error": str(e)}


@app.get("/api/servers")
async def api_servers():
    return [{"id": rs["id"], "name": rs["name"], "group": rs["group"],
             "host": rs["host"], "type": rs.get("type", "frr"),
             "note": rs.get("note", ""), "enabled": rs.get("enabled", True)}
            for rs in CFG["route_servers"]]


@app.get("/api/latam-ixps")
async def api_latam_ixps():
    return {"ok": True, "count": 0,
            "note": "Ranking disponible en el tab LATAM IXPs del frontend", "ixps": []}


# ---------------------------------------------------------------------------
# Cloud Status
# ---------------------------------------------------------------------------

CLOUD_PROVIDERS = CFG.get("cloud_providers", [])
CLOUD_PROVIDERS = [p for p in CLOUD_PROVIDERS if p.get("enabled", True)]

_cloud_cache: dict = {}
_cloud_cache_ts: float = 0
CLOUD_CACHE_TTL = CFG.get("cache", {}).get("cloud_status_ttl", 120)


def fetch_cloud_status(provider: dict) -> dict:
    stype = provider.get("status_type", "statuspage")
    try:
        headers = {"Accept": "application/json, text/xml, */*",
                   "User-Agent": "PIT-Chile-LG/2.1"}

        if stype == "statuspage":
            req = urllib.request.Request(provider["status_url"], headers=headers)
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            status_obj  = data.get("status", {})
            indicator   = status_obj.get("indicator", "unknown")
            description = status_obj.get("description", "Operational")

        elif stype == "gcp":
            req = urllib.request.Request(provider["status_url"], headers=headers)
            with urllib.request.urlopen(req, timeout=8) as resp:
                raw = resp.read()
            data   = json.loads(raw)
            active = [i for i in data if not i.get("end")] if isinstance(data, list) else []
            indicator   = "none" if not active else "minor"
            description = "Operational" if not active else str(len(active)) + " incidente(s) activo(s)"

        elif stype == "rss":
            req = urllib.request.Request(provider["status_url"], headers=headers)
            with urllib.request.urlopen(req, timeout=8) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            keywords    = ["disruption", "outage", "degraded", "investigating", "incident"]
            has_issue   = any(k in raw[:5000].lower() for k in keywords)
            indicator   = "minor" if has_issue else "none"
            description = "Posible incidente activo" if has_issue else "Operational"

        else:
            indicator, description = "unknown", "Tipo desconocido"

        return {"indicator": indicator, "description": description or "Operational", "ok": True}

    except Exception as e:
        return {"indicator": "unknown", "description": "No disponible", "ok": False, "error": str(e)}


@app.get("/api/cloud-status")
async def api_cloud_status():
    global _cloud_cache, _cloud_cache_ts
    now = time.time()
    if _cloud_cache and (now - _cloud_cache_ts) < CLOUD_CACHE_TTL:
        return _cloud_cache

    tasks    = [asyncio.to_thread(fetch_cloud_status, p) for p in CLOUD_PROVIDERS]
    statuses = await asyncio.gather(*tasks, return_exceptions=True)
    results  = []
    for provider, status in zip(CLOUD_PROVIDERS, statuses):
        if isinstance(status, Exception):
            status = {"indicator": "unknown", "description": "Error", "ok": False}
        results.append({
            "name":         provider["name"],
            "short":        provider.get("short", ""),
            "asn":          provider.get("asn", ""),
            "color":        provider.get("color", "#999"),
            "page_url":     provider.get("page_url", ""),
            "bgp_prefix":   provider.get("bgp_prefix", ""),
            "pit_maps_url": provider.get("pit_maps_url"),
            "indicator":    status.get("indicator", "unknown"),
            "description":  status.get("description", ""),
            "ok":           status.get("ok", False),
        })

    _cloud_cache    = {"ok": True, "providers": results,
                       "cached_at": datetime.utcnow().isoformat() + "Z"}
    _cloud_cache_ts = now
    return _cloud_cache


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": CFG["server"]["title"],
            "version": CFG.get("server", {}).get("version", "2.1.0")}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app",
                host=CFG["server"]["host"],
                port=CFG["server"]["port"],
                reload=CFG["server"]["debug"],
                log_level="debug" if CFG["server"]["debug"] else "info")
