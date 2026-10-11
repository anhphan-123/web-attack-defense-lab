import json
import re
import subprocess
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import urlsplit

LOG_FILE = "/var/log/purple-team/web-enumeration.json"
WINDOW = 60
THRESHOLD = 10
COOLDOWN = 60

pattern = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3}) - - '
    r'\[([^\]]+)\] '
    r'"(GET|HEAD) (\S+) HTTP/[\d.]+" '
    r'(\d{3})\b'
)

history = defaultdict(deque)
last_alert = {}

print("[*] Web Enumeration Detector started", flush=True)
print("[*] Monitoring Nginx access logs...", flush=True)

process = subprocess.Popen(
    ["docker", "logs", "-f", "--tail", "0", "web-waf"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    errors="replace"
)

with open(LOG_FILE, "a", buffering=1) as output:
    for line in process.stdout:
        match = pattern.search(line)

        if not match:
            continue

        ip, timestamp, method, uri, status = match.groups()
        path = urlsplit(uri).path

        if not path.startswith("/rest/"):
            continue

        try:
            now = datetime.strptime(
                timestamp, "%d/%b/%Y:%H:%M:%S %z"
            )
        except ValueError:
            continue

        events = history[ip]
        events.append((now, path, int(status)))

        while events and (now - events[0][0]).total_seconds() > WINDOW:
            events.popleft()

        unique_paths = {event[1] for event in events}

        if len(unique_paths) < THRESHOLD:
            continue

        previous = last_alert.get(ip)

        if previous and (now - previous).total_seconds() < COOLDOWN:
            continue

        last_alert[ip] = now

        blocked = sum(1 for event in events if event[2] == 403)

        alert = {
            "event_source": "web_enumeration_detector",
            "attack_type": "WebEnumeration",
            "src_ip": ip,
            "request_count": len(events),
            "unique_paths": len(unique_paths),
            "window_seconds": WINDOW,
            "http_403_count": blocked,
            "sample_paths": ",".join(sorted(unique_paths)[:10]),
            "detection": "suspicious_path_enumeration"
        }

        output.write(json.dumps(alert) + "\n")

        print("\n=== WEB ENUMERATION DETECTED ===", flush=True)
        print("Source IP:", ip, flush=True)
        print("Requests:", len(events), flush=True)
        print("Unique Paths:", len(unique_paths), flush=True)
        print("Time Window:", WINDOW, "seconds", flush=True)
        print("HTTP 403:", blocked, flush=True)
        print("Detection: Suspicious Path Enumeration", flush=True)
        print("=" * 40, flush=True)
