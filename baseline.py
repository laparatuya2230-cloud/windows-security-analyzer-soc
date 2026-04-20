import json
from pathlib import Path

BASELINE_FILE = Path("baseline.json")


def _normalize(results):
    """Reduce los resultados a lo importante para comparar."""
    ports = sorted([p.get("port") for p in results.get("open_ports", []) if p.get("port")])
    services = sorted([s.get("name") for s in results.get("services", []) if s.get("name")])
    startup = sorted([str(s) for s in results.get("startup", [])])
    users = sorted([u.get("name") for u in results.get("users", []) if u.get("name")])

    return {
        "ports": ports,
        "services": services,
        "startup": startup,
        "users": users
    }


def save_baseline(results):
    data = _normalize(results)
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def load_baseline():
    if not BASELINE_FILE.exists():
        return None
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def compare_with_baseline(results):
    baseline = load_baseline()
    if not baseline:
        return [], []

    current = _normalize(results)

    anomalies = []
    removed = []

    for key in current:
        old = set(baseline.get(key, []))
        new = set(current.get(key, []))

        added = new - old
        removed_items = old - new

        for a in added:
            anomalies.append((key, a))

        for r in removed_items:
            removed.append((key, r))

    return anomalies, removed