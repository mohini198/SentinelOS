"""Validates action params against the allowlist.yaml schema. Unknown params are rejected."""
from __future__ import annotations

import re

OPTIONAL = {"reason", "max_size_mb"}


def validate_params(spec: dict, params: dict) -> list[str]:
    errs: list[str] = []
    if not isinstance(params, dict):
        return ["params must be an object"]
    for k in params:
        if k not in spec:
            errs.append(f"unexpected param {k!r}")
    for k, rule in spec.items():
        if k not in params:
            if k not in OPTIONAL:
                errs.append(f"missing param {k!r}")
            continue
        v, t = params[k], rule.get("type")
        if t == "integer":
            ok = isinstance(v, int) and not isinstance(v, bool)
        elif t == "number":
            ok = isinstance(v, (int, float)) and not isinstance(v, bool)
        elif t == "string":
            ok = isinstance(v, str)
        else:
            ok = False
        if not ok:
            errs.append(f"{k!r} must be {t}")
            continue
        if "enum" in rule and rule["enum"] and v not in rule["enum"]:
            errs.append(f"{k!r} must be one of {rule['enum']}")
        if "minimum" in rule and rule["minimum"] is not None and v < rule["minimum"]:
            errs.append(f"{k!r} must be >= {rule['minimum']}")
        if "maximum" in rule and rule["maximum"] is not None and v > rule["maximum"]:
            errs.append(f"{k!r} must be <= {rule['maximum']}")
        if t == "string":
            if "\n" in v or "\x00" in v:
                errs.append(f"{k!r} contains control characters")
            if rule.get("maxLength") is not None and len(v) > rule["maxLength"]:
                errs.append(f"{k!r} longer than {rule['maxLength']}")
            if rule.get("pattern") and not re.search(rule["pattern"], v):
                errs.append(f"{k!r} does not match required pattern")
    return errs