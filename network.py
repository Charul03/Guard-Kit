import socket
import threading
from typing import List


def parse_ports(port_str: str) -> List[int]:
    """
    Accepts strings like:
      "80,443,8000-8100"  -> returns list of ints
    Empty string -> default common ports 1-1024
    """
    if not port_str:
        return list(range(1, 1025))
    ports = set()
    parts = port_str.split(',')
    for p in parts:
        p = p.strip()
        if '-' in p:
            start, end = p.split('-', 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(p))
    return sorted(p for p in ports if 1 <= p <= 65535)


def _scan_one(host: str, port: int, timeout: float, results: list):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                results.append(port)
    except Exception:
        pass


def port_scan(host: str, ports=None, timeout: float = 0.8, max_threads: int = 200):
    """
    Scan specified ports on host. Returns a user-friendly text summary.
    """
    if ports is None:
        ports = list(range(1, 1025))

    print(f"🔍 Starting scan on host: {host}")
    print(f"⏱️ Scanning {len(ports)} ports... Please wait.")

    results = []
    threads = []
    for port in ports:
        t = threading.Thread(target=_scan_one, args=(host, port, timeout, results))
        t.start()
        threads.append(t)
        if len(threads) >= max_threads:
            for th in threads:
                th.join()
            threads = []
    for th in threads:
        th.join()

    if results:
        result_text = f"\n✅ Scan complete! Found {len(results)} open ports on {host}:\n"
        result_text += "-" * 45 + "\n"
        for port in sorted(results):
            result_text += f"🔓 Port {port} is OPEN\n"
        result_text += "-" * 45
    else:
        result_text = f"\n🛡️ No open ports found on {host} in the scanned range."

    return result_text
