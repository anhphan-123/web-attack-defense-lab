import json
import subprocess

process = subprocess.Popen(
    ["docker", "logs", "-f", "--tail", "0", "web-waf"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    errors="replace"
)

with open("/var/log/purple-team/waf-events.json", "a", buffering=1) as output:
    for line in process.stdout:
        try:
            data = json.loads(line)
            tx = data.get("transaction")

            if not isinstance(tx, dict):
                continue

        except (ValueError, TypeError):
            continue

        rule_ids = []

        for msg in tx.get("messages", []):
            if isinstance(msg, dict):
                rule_id = msg.get("details", {}).get("ruleId")
                if rule_id:
                    rule_ids.append(str(rule_id))

        if any(r.startswith("941") for r in rule_ids):
            attack_type = "XSS"
        elif any(r.startswith("942") for r in rule_ids):
            attack_type = "SQLi"
        else:
            attack_type = "Other"

        blocked = bool(tx.get("is_interrupted"))

        if attack_type == "Other" and not blocked:
            continue

        event = {
            "event_source": "modsecurity_waf",
            "attack_type": attack_type,
            "src_ip": tx.get("client_ip"),
            "request_uri": tx.get("request", {}).get("uri", "")[:512],
            "http_code": tx.get("response", {}).get("http_code"),
            "action": "blocked" if blocked else "detected",
            "rule_ids": ",".join(rule_ids),
            "transaction_id": tx.get("unique_id")
        }

        output.write(json.dumps(event) + "\n")
