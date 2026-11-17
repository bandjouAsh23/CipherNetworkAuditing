import { enforceHttpsUrl } from './targetValidation';

export function generatePythonPcAgent(): string {
  return `#!/usr/bin/env python3
"""
CipherNetworkAuditing — Agent d'Audit Réseau Local (PC)
Outil défensif autonome (Python 3 standard library uniquement).
Découvre les appareils autorisés d'une IP ou d'un sous-réseau cible,
vérifie l'état des ports (ouvert / fermé / filtré), contrôle TLS/HTTPS
et exporte ou transfère les résultats en HTTPS vers CipherNetworkAuditing.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone

COMMON_PORTS = [
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "domain"),
    (80, "http"),
    (135, "msrpc"),
    (139, "netbios-ssn"),
    (443, "https"),
    (445, "microsoft-ds"),
    (554, "rtsp"),
    (3306, "mysql"),
    (3389, "ms-wbt-server"),
    (5432, "postgresql"),
    (5900, "vnc"),
    (6379, "redis"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (9100, "jetdirect"),
    (27017, "mongodb"),
]


def detect_local_subnet() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        parts = local_ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except OSError:
        pass
    return "192.168.1.0/24"


def read_arp_table() -> dict:
    mac_map = {}
    try:
        cmd = ["arp", "-a"]
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=4)
        for line in output.splitlines():
            ip_match = re.search(r"(\\d+\\.\\d+\\.\\d+\\.\\d+)", line)
            mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
            if ip_match and mac_match:
                mac_map[ip_match.group(1)] = mac_match.group(0).replace("-", ":").upper()
    except Exception:
        pass
    return mac_map


def ping_host(ip: str) -> bool:
    is_win = platform.system().lower().startswith("win")
    cmd = ["ping", "-n", "1", "-w", "350", ip] if is_win else ["ping", "-c", "1", "-W", "1", ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5)
        return res.returncode == 0
    except Exception:
        return False


def inspect_tls_banner(ip: str, port: int, timeout_s: float = 0.6) -> tuple[bool, str | None]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout_s) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=ip) as tls_sock:
                proto = tls_sock.version() or "TLS"
                return True, f"HTTPS ({proto})"
    except Exception:
        return False, None


def probe_port(ip: str, port: int, service: str, timeout_s: float = 0.45) -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    state = "closed"
    banner = None
    product = None
    version = None
    tls_enabled = False if port in (21, 23, 80, 8080, 5900, 2375) else None

    try:
        code = sock.connect_ex((ip, port))
        if code == 0:
            state = "open"
            if port in (443, 8443):
                sock.close()
                tls_ok, tls_banner = inspect_tls_banner(ip, port, timeout_s=0.6)
                tls_enabled = tls_ok
                banner = tls_banner
            else:
                try:
                    if port in (80, 8080):
                        sock.sendall(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
                    raw = sock.recv(256).decode("utf-8", errors="ignore").strip()
                    if raw:
                        first_line = raw.splitlines()[0][:120]
                        banner = first_line
                        if "OpenSSH_" in first_line:
                            product = "OpenSSH"
                            m = re.search(r"OpenSSH_([0-9.p]+)", first_line)
                            if m:
                                version = m.group(1)
                        elif "Apache/" in first_line:
                            product = "Apache httpd"
                            m = re.search(r"Apache/([0-9.]+)", first_line)
                            if m:
                                version = m.group(1)
                        elif "nginx/" in first_line:
                            product = "nginx"
                            m = re.search(r"nginx/([0-9.]+)", first_line)
                            if m:
                                version = m.group(1)
                except OSError:
                    pass
        elif code in (11, 10060, 110):  # EAGAIN / WSAETIMEDOUT / ETIMEDOUT
            state = "filtered"
    except socket.timeout:
        state = "filtered"
    except OSError:
        state = "closed"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    entry = {
        "port": port,
        "protocol": "tcp",
        "state": state,
        "service": service,
    }
    if product:
        entry["product"] = product
    if version:
        entry["version"] = version
    if banner:
        entry["banner"] = banner
    if tls_enabled is not None:
        entry["tlsEnabled"] = tls_enabled
    return entry


def inspect_host(ip: str, mac_map: dict, force_probe_all: bool = False) -> dict | None:
    alive = ping_host(ip)
    ports = []
    quick_ports = [p for p, _ in COMMON_PORTS] if (alive or force_probe_all) else [22, 80, 443, 445, 3389, 8080]

    for port_num, svc in COMMON_PORTS:
        if port_num not in quick_ports:
            continue
        result = probe_port(ip, port_num, svc)
        if result["state"] in ("open", "filtered") or alive or force_probe_all:
            ports.append(result)

    has_open_or_filtered = any(p["state"] in ("open", "filtered") for p in ports)
    if not alive and not has_open_or_filtered:
        return None

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except OSError:
        hostname = f"hote-{ip.replace('.', '-')}.local"

    return {
        "id": f"pc-{ip.replace('.', '-')}",
        "ip": ip,
        "hostname": hostname,
        "mac": mac_map.get(ip),
        "deviceType": "gateway" if ip.endswith(".1") or ip.endswith(".254") else "unknown",
        "isGateway": ip.endswith(".1") or ip.endswith(".254"),
        "ports": [p for p in ports if p["state"] != "closed" or p["port"] in (21, 22, 23, 80, 443, 3389)],
    }


def upload_over_https(https_base_url: str, payload: dict) -> None:
    if not https_base_url.startswith("https://"):
        raise ValueError("Transfert refusé : le protocole HTTPS (https://) est obligatoire pour l'envoi des résultats.")
    endpoint = https_base_url.rstrip("/") + "/api/analyze-nmap"
    body = json.dumps({
        "profileName": f"Agent PC — {payload.get('subnet', 'Cible')}",
        "rawInput": json.dumps(payload),
    }).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"Erreur serveur HTTPS ({resp.status})")
    print(f"[HTTPS] Résultats transférés de manière chiffrée vers {endpoint}")


def main():
    parser = argparse.ArgumentParser(description="CipherNetworkAuditing — Agent d'audit réseau autorisé")
    parser.add_argument("--target", default=None, help="IP ou sous-réseau CIDR autorisé (ex: 192.168.1.10 ou 192.168.1.0/24)")
    parser.add_argument("--subnet", default=None, help="Alias rétrocompatible pour --target")
    parser.add_argument("--authorized", action="store_true", help="Confirmer l'autorisation explicite du propriétaire")
    parser.add_argument("--upload-https-url", default=None, help="URL HTTPS de CipherNetworkAuditing pour transfert chiffré")
    parser.add_argument("--output", default="ciphernetwork_scan.json", help="Fichier JSON de sortie")
    args = parser.parse_args()

    target_str = args.target or args.subnet or detect_local_subnet()
    if not args.authorized:
        answer = input(f"Confirmez-vous avoir l'autorisation explicite d'auditer {target_str} ? (oui/non) : ").strip().lower()
        if answer not in ("oui", "o", "yes", "y"):
            raise SystemExit("Analyse annulée : autorisation explicite requise.")

    if "/" in target_str:
        network = ipaddress.ip_network(target_str, strict=False)
        hosts = [str(ip) for ip in network.hosts()][:254]
        is_single = False
        target_label = str(network)
    else:
        ip_obj = ipaddress.ip_address(target_str)
        hosts = [str(ip_obj)]
        is_single = True
        target_label = str(ip_obj)

    mac_map = read_arp_table()
    print(f"[CipherNetworkAuditing] Audit défensif autorisé de {target_label} ({len(hosts)} hôte(s))...")
    devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(inspect_host, ip, mac_map, is_single): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            dev = future.result()
            if dev:
                devices.append(dev)
                open_cnt = sum(1 for p in dev["ports"] if p["state"] == "open")
                print(f"  + {dev['ip']:15s} | {dev['hostname']:30s} | {open_cnt} port(s) ouvert(s)")

    devices.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    payload = {
        "scanner": "CipherNetworkAuditing PC Agent (TLS/HTTPS Ready)",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "subnet": target_label,
        "devices": devices,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(f"\\n[OK] {len(devices)} appareil(s) exporté(s) vers {os.path.abspath(args.output)}")
    if args.upload_https_url:
        upload_over_https(args.upload_https_url, payload)
    else:
        print("Importez ce fichier JSON dans CipherNetworkAuditing (transfert HTTPS).")


if __name__ == "__main__":
    main()
`;
}

export function generateWindowsBatchLauncher(appUrl: string): string {
  const secureUrl = enforceHttpsUrl(appUrl);
  return `@echo off
title CipherNetworkAuditing — Lanceur PC (HTTPS)
echo ====================================================
echo   CipherNetworkAuditing - Application d'Audit Reseau
echo   Transport chiffre : HTTPS / TLS
echo ====================================================
echo.
echo 1. Ouverture de l'application en mode fenetre bureau...
start "" msedge --app="${secureUrl}" 2>nul || start "" chrome --app="${secureUrl}" 2>nul || start "" "${secureUrl}"
echo.
echo Astuce : Pour analyser une cible autorisee sur votre LAN :
echo   python cipher_audit_pc.py --target 192.168.1.0/24 --authorized --upload-https-url "${secureUrl}"
echo.
pause
`;
}

export function generateUnixShellLauncher(appUrl: string): string {
  const secureUrl = enforceHttpsUrl(appUrl);
  return `#!/usr/bin/env bash
set -e

APP_URL="${secureUrl}"
echo "=== CipherNetworkAuditing — Lanceur Desktop (HTTPS) ==="

if command -v google-chrome >/dev/null 2>&1; then
  google-chrome --app="$APP_URL" >/dev/null 2>&1 &
elif command -v chromium >/dev/null 2>&1; then
  chromium --app="$APP_URL" >/dev/null 2>&1 &
elif command -v open >/dev/null 2>&1; then
  open "$APP_URL"
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$APP_URL"
else
  echo "Ouvrez cette URL HTTPS dans votre navigateur : $APP_URL"
fi

if [ -f "./cipher_audit_pc.py" ] && command -v python3 >/dev/null 2>&1; then
  echo "Agent Python détecté : exécutez 'python3 ./cipher_audit_pc.py --target <IP_CIBLE> --authorized --upload-https-url $APP_URL'"
fi
`;
}
