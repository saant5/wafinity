import json
import os
from typing import Any, Dict, List

RULES_DIR = "rules"
RULES_FILE = os.path.join(RULES_DIR, "waf_rules.json")

DEFAULT_RULES = {
    "enabled": True,
    "rules": [
        {"id": "R1", "type": "BLOCK_CONTAINS", "value": "<script>", "severity": 40},
        {"id": "R2", "type": "BLOCK_CONTAINS", "value": "union select", "severity": 50},
    ]
}

def _ensure_file():
    os.makedirs(RULES_DIR, exist_ok=True)
    if not os.path.exists(RULES_FILE):
        save_rules(DEFAULT_RULES)

def load_rules() -> Dict[str, Any]:
    _ensure_file()
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_rules(data: Dict[str, Any]) -> None:
    os.makedirs(RULES_DIR, exist_ok=True)
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def list_rules() -> List[Dict[str, Any]]:
    data = load_rules()
    return data.get("rules", [])

def add_rule(rule: Dict[str, Any]) -> None:
    data = load_rules()
    rules = data.get("rules", [])
    rules.append(rule)
    data["rules"] = rules
    save_rules(data)

def delete_rule(rule_id: str) -> bool:
    data = load_rules()
    rules = data.get("rules", [])
    new_rules = [r for r in rules if r.get("id") != rule_id]
    changed = len(new_rules) != len(rules)
    data["rules"] = new_rules
    save_rules(data)
    return changed