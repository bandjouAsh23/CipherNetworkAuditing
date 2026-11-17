#!/usr/bin/env python3
"""
CipherNetworkAuditing — Exécutable PC Autonome (Windows / macOS / Linux)
Lance localement l'interface 3D complète (dist/) ainsi que le moteur de sondage
réseau LAN (hôte local, cible IP/CIDR autorisée, détection de ports & bannières)
sans aucune dépendance externe (Python 3 standard library uniquement).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.server
import ipaddress
import json
import mimetypes
import os
import platform
import re
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import zipfile
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
    (161, "snmp"),
    (443, "https"),
    (445, "microsoft-ds"),
    (554, "rtsp"),
    (2375, "docker"),
    (3000, "http-app"),
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


def get_local_primary_ip() -> tuple[str, str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        parts = ip.split(".")
        if len(parts) == 4:
            return ip, f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except OSError:
        pass
    return "127.0.0.1", "127.0.0.0/8"


def read_arp_table() -> dict[str, str]:
    mac_map: dict[str, str] = {}
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL, timeout=4)
        for line in output.splitlines():
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
            if ip_match and mac_match:
                mac_map[ip_match.group(1)] = mac_match.group(0).replace("-", ":").upper()
    except Exception:
        pass
    return mac_map


def ping_host(ip: str) -> bool:
    is_win = platform.system().lower().startswith("win")
    cmd = ["ping", "-n", "1", "-w", "300", ip] if is_win else ["ping", "-c", "1", "-W", "1", ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.2)
        return res.returncode == 0
    except Exception:
        return False


def inspect_tls_banner(ip: str, port: int, timeout_s: float = 0.45) -> tuple[bool, str | None]:
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


def probe_port(ip: str, port: int, service: str, timeout_s: float = 0.28) -> dict:
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
                tls_ok, tls_banner = inspect_tls_banner(ip, port)
                tls_enabled = tls_ok
                banner = tls_banner
            else:
                try:
                    if port in (80, 8080, 3000):
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    raw = sock.recv(256).decode("utf-8", errors="ignore").strip()
                    if raw:
                        first_line = raw.splitlines()[0][:120]
                        banner = first_line
                        for regex, prod_name in (
                            (r"OpenSSH_([0-9.p]+)", "OpenSSH"),
                            (r"Apache/([0-9.]+)", "Apache httpd"),
                            (r"nginx/([0-9.]+)", "nginx"),
                        ):
                            m = re.search(regex, first_line)
                            if m:
                                product = prod_name
                                version = m.group(1)
                                break
                except OSError:
                    pass
        elif code in (11, 10060, 110):
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

    entry: dict = {
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


def inspect_host(ip: str, mac_map: dict[str, str], force_probe_all: bool = False) -> dict | None:
    t0 = time.monotonic()
    alive = True if ip == "127.0.0.1" else ping_host(ip)
    ports = []
    probe_list = COMMON_PORTS if (alive or force_probe_all) else [p for p in COMMON_PORTS if p[0] in (22, 80, 443, 445, 3389, 8080)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as port_pool:
        futures = [port_pool.submit(probe_port, ip, port_num, svc) for port_num, svc in probe_list]
        for fut in futures:
            res = fut.result()
            if res["state"] in ("open", "filtered") or alive or force_probe_all:
                ports.append(res)

    has_open = any(p["state"] == "open" for p in ports)
    has_closed = any(p["state"] == "closed" for p in ports)
    if not alive and not has_open and not (force_probe_all and has_closed):
        return None

    try:
        hostname = socket.gethostname() if ip == "127.0.0.1" else socket.gethostbyaddr(ip)[0]
    except OSError:
        hostname = f"hote-{ip.replace('.', '-')}.local"

    return {
        "id": f"pc-{ip.replace('.', '-')}",
        "ip": ip,
        "hostname": hostname,
        "mac": mac_map.get(ip),
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})" if ip in ("127.0.0.1", get_local_primary_ip()[0]) else None,
        "deviceType": "gateway" if ip.endswith(".1") or ip.endswith(".254") else "server",
        "latencyMs": round(max(0.4, (time.monotonic() - t0) * 100), 1),
        "isGateway": ip.endswith(".1") or ip.endswith(".254"),
        "ports": [p for p in ports if p["state"] != "closed" or p["port"] in (21, 22, 23, 80, 443, 3389)],
    }


def validate_target(raw_target: str, authorized: bool) -> tuple[bool, int, dict]:
    if not authorized:
        return False, 403, {"error": "Confirmation d'autorisation explicite requise avant toute analyse."}
    trimmed = raw_target.strip()
    if not trimmed:
        return False, 400, {"error": "Veuillez saisir une adresse IPv4 ou plage CIDR (/24 à /32)."}
    try:
        if "/" in trimmed:
            net_obj = ipaddress.ip_network(trimmed, strict=False)
            if net_obj.version != 4 or net_obj.prefixlen < 24:
                return False, 400, {"error": "La cible doit être une plage IPv4 comprise entre /24 et /32."}
            check_ip = net_obj.network_address
            hosts = [str(ip) for ip in net_obj.hosts()][:32] if net_obj.prefixlen < 31 else [str(ip) for ip in net_obj][:2]
            normalized = str(net_obj)
        else:
            ip_obj = ipaddress.ip_address(trimmed)
            if ip_obj.version != 4:
                return False, 400, {"error": "Seules les adresses IPv4 sont prises en charge."}
            check_ip = ip_obj
            hosts = [str(ip_obj)]
            normalized = str(ip_obj)
    except ValueError:
        return False, 400, {"error": "Adresse IPv4 ou format CIDR invalide."}

    if check_ip.is_link_local or check_ip.is_multicast or check_ip.is_unspecified:
        return False, 400, {"error": "Les adresses link-local (169.254.0.0/16), multicast ou 0.0.0.0 sont bloquées."}

    return True, 200, {"normalized": normalized, "hosts": hosts, "isSingle": len(hosts) == 1}


class AssetLoader:
    def __init__(self) -> None:
        self.archive_path = os.path.abspath(sys.argv[0]) if sys.argv else ""
        self.is_zip = bool(self.archive_path and zipfile.is_zipfile(self.archive_path))
        self.local_dist = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")

    def read_asset(self, url_path: str) -> tuple[bytes, str] | None:
        clean = url_path.split("?", 1)[0].lstrip("/") or "index.html"
        if ".." in clean:
            return None

        if self.is_zip:
            with zipfile.ZipFile(self.archive_path, "r") as zf:
                candidate = f"dist/{clean}"
                if candidate not in zf.namelist():
                    candidate = "dist/index.html"
                if candidate in zf.namelist():
                    ctype = mimetypes.guess_type(candidate)[0] or "application/octet-stream"
                    return zf.read(candidate), ctype
        elif os.path.isdir(self.local_dist):
            candidate = os.path.join(self.local_dist, clean)
            if not os.path.isfile(candidate):
                candidate = os.path.join(self.local_dist, "index.html")
            if os.path.isfile(candidate):
                with open(candidate, "rb") as f:
                    ctype = mimetypes.guess_type(candidate)[0] or "application/octet-stream"
                    return f.read(), ctype
        return None


ASSET_LOADER = AssetLoader()


class CipherRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    tls_active = False

    def log_message(self, format: str, *args) -> None:
        return

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > 8 * 1024 * 1024:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/health":
            self._send_json(200, {
                "ok": True,
                "mode": "pc-executable",
                "transport": "HTTPS/TLS" if self.tls_active else "Loopback-127.0.0.1",
            })
            return

        if parsed.path == "/api/local-host":
            t0 = time.monotonic()
            local_ip, subnet = get_local_primary_ip()
            mac_map = read_arp_table()
            targets = list(dict.fromkeys([local_ip, "127.0.0.1"]))
            devices = [d for d in (inspect_host(ip, mac_map, True) for ip in targets) if d is not None]
            self._send_json(200, {
                "needsClientEval": True,
                "id": f"local-pc-{int(time.time())}",
                "profileName": f"Poste PC ({platform.node() or 'Local'})",
                "subnet": subnet,
                "sourceType": "local_host",
                "devices": devices,
                "durationMs": max(80, int((time.monotonic() - t0) * 1000)),
            })
            return

        asset = ASSET_LOADER.read_asset(parsed.path)
        if asset is None:
            self._send_json(404, {"error": "Ressource introuvable dans l'exécutable."})
            return

        data, ctype = asset
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8" if ctype.startswith("text/") or ctype == "application/javascript" else ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        body = self._read_json_body()

        if parsed.path == "/api/scan-target":
            t0 = time.monotonic()
            ok, status, info = validate_target(str(body.get("target", "")), body.get("authorized") is True)
            if not ok:
                self._send_json(status, info)
                return

            mac_map = read_arp_table()
            devices: list[dict] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                futs = [pool.submit(inspect_host, ip, mac_map, info["isSingle"]) for ip in info["hosts"]]
                for fut in futs:
                    dev = fut.result()
                    if dev is not None:
                        devices.append(dev)

            if not devices:
                self._send_json(200, {
                    "reachable": False,
                    "target": info["normalized"],
                    "message": f"Aucun hôte joignable sur {info['normalized']} depuis ce PC.",
                })
                return

            self._send_json(200, {
                "reachable": True,
                "target": info["normalized"],
                "needsClientEval": True,
                "id": f"target-pc-{int(time.time())}",
                "profileName": f"Cible PC autorisée ({info['normalized']})",
                "subnet": info["normalized"],
                "sourceType": "target_scan",
                "devices": devices,
                "durationMs": max(80, int((time.monotonic() - t0) * 1000)),
            })
            return

        if parsed.path == "/api/analyze-nmap":
            self._send_json(200, {
                "needsClientParse": True,
                "rawInput": str(body.get("rawInput", "")),
                "profileName": str(body.get("profileName", "Import Scan PC")),
            })
            return

        self._send_json(404, {"error": "Endpoint inconnu."})


class ThreadingLoopbackServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def maybe_create_local_tls(cert_dir: str) -> tuple[str, str] | None:
    openssl_bin = shutil.which("openssl")
    if not openssl_bin:
        return None
    cert_path = os.path.join(cert_dir, "cert.pem")
    key_path = os.path.join(cert_dir, "key.pem")
    try:
        subprocess.run(
            [
                openssl_bin,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                "30",
                "-nodes",
                "-subj",
                "/CN=127.0.0.1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=8,
        )
        return cert_path, key_path
    except Exception:
        return None


def launch_desktop_window(url: str) -> None:
    for browser in ("msedge", "chrome", "google-chrome", "chromium", "chromium-browser"):
        exe = shutil.which(browser)
        if exe:
            try:
                subprocess.Popen(
                    [exe, f"--app={url}", "--new-window"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return
            except Exception:
                pass
    webbrowser.open(url)


def run_cli_scan(target: str, authorized: bool, output_path: str) -> None:
    ok, _, info = validate_target(target, authorized)
    if not ok:
        raise SystemExit(info["error"])
    mac_map = read_arp_table()
    devices: list[dict] = []
    print(f"[CipherNetworkAuditing] Audit autorisé de {info['normalized']}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        futs = [pool.submit(inspect_host, ip, mac_map, info["isSingle"]) for ip in info["hosts"]]
        for fut in futs:
            dev = fut.result()
            if dev is not None:
                devices.append(dev)
                open_cnt = sum(1 for p in dev["ports"] if p["state"] == "open")
                print(f"  + {dev['ip']:15s} | {dev['hostname']:28s} | {open_cnt} port(s) ouvert(s)")
    payload = {
        "scanner": "CipherNetworkAuditing Executable",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "subnet": info["normalized"],
        "devices": devices,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"[OK] {len(devices)} appareil(s) enregistré(s) dans {os.path.abspath(output_path)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="CipherNetworkAuditing — Exécutable PC autonome")
    parser.add_argument("--cli", action="store_true", help="Exécuter en mode ligne de commande sans interface graphique")
    parser.add_argument("--target", default=None, help="IP ou sous-réseau CIDR autorisé")
    parser.add_argument("--authorized", action="store_true", help="Confirmer l'autorisation explicite")
    parser.add_argument("--output", default="ciphernetwork_scan.json", help="Fichier JSON de sortie (--cli)")
    parser.add_argument("--port", type=int, default=0, help="Port local (0 = automatique)")
    parser.add_argument("--no-browser", action="store_true", help="Ne pas ouvrir automatiquement la fenêtre")
    parser.add_argument("--no-tls", action="store_true", help="Désactiver TLS auto-signé local")
    args = parser.parse_args()

    if args.cli:
        target = args.target or get_local_primary_ip()[1]
        run_cli_scan(target, args.authorized, args.output)
        return

    server = ThreadingLoopbackServer(("127.0.0.1", args.port), CipherRequestHandler)
    actual_port = server.server_address[1]
    scheme = "http"

    temp_dir = tempfile.mkdtemp(prefix="ciphernetwork-tls-")
    try:
        if not args.no_tls:
            certs = maybe_create_local_tls(temp_dir)
            if certs:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=certs[0], keyfile=certs[1])
                server.socket = ctx.wrap_socket(server.socket, server_side=True)
                CipherRequestHandler.tls_active = True
                scheme = "https"

        app_url = f"{scheme}://127.0.0.1:{actual_port}/"
        print(f"CipherNetworkAuditing exécuté localement sur {app_url}")
        print("Appuyez sur Ctrl+C pour fermer l'application.")

        if not args.no_browser:
            threading.Timer(0.45, launch_desktop_window, args=(app_url,)).start()

        server.serve_forever()
    except KeyboardInterrupt:
        print("\nFermeture de CipherNetworkAuditing.")
    finally:
        server.server_close()
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
