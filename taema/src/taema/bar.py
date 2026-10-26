"""Status bar feed models and formats (issue #64).

``model_from_status`` reduces a daemon status reply to the bar model;
``render`` writes one line per state change in waybar, i3bar, json, or
plain formats. The quickshell widget consumes the json lines.
"""

from __future__ import annotations

import json

__all__ = [
    "FORMATS",
    "error_model",
    "format_memory",
    "model_from_status",
    "render",
    "render_text",
    "render_tooltip",
]

FORMATS = ("waybar", "i3bar", "json", "plain")

CLASS_COLORS = {
    "ok": "#8a8a8a",
    "review": "#e5c07c",
    "pressure": "#e06c75",
    "hold": "#61afef",
    "error": "#ff5555",
}


def format_memory(value):
    """Human bytes matching the CLI views: 9979123456 -> 9.3G."""
    amount = float(max(0, value))
    for unit in ("B", "K", "M", "G", "T"):
        if amount < 1024 or unit == "T":
            return "%d" % amount if unit == "B" else "%.1f%s" % (amount, unit)
        amount /= 1024.0
    return "%.1fT" % amount


def _number(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def model_from_status(reply):
    """Reduce a daemon status reply to the bar model."""
    reply = reply if isinstance(reply, dict) else {}
    guard = reply.get("guard")
    guard = guard if isinstance(guard, dict) else {}
    agents = reply.get("agents")
    agents = agents if isinstance(agents, dict) else {}
    frozen = reply.get("frozen_scopes")
    frozen = frozen if isinstance(frozen, list) else []
    hold = reply.get("hold") or ""
    pressure = guard.get("active") is True
    reviews = _number(reply.get("reviews"))
    if hold:
        kind = "hold"
    elif pressure:
        kind = "pressure"
    elif reviews > 0:
        kind = "review"
    else:
        kind = "ok"
    return {
        "mode": reply.get("mode") or "unknown",
        "profile": reply.get("profile") or "auto",
        "reviews": reviews,
        "frozen": len(frozen),
        "deprioritized": _number(reply.get("deprioritized")),
        "freed_today_bytes": _number(reply.get("freed_today_bytes")),
        "hold": hold,
        "pressure": pressure,
        "agent_running": any(
            isinstance(record, dict) and record.get("state") == "up"
            for record in agents.values()
        ),
        "class": kind,
    }


def error_model():
    """The bar model when the daemon cannot be reached."""
    return {
        "mode": "unknown",
        "profile": "auto",
        "reviews": 0,
        "frozen": 0,
        "deprioritized": 0,
        "freed_today_bytes": 0,
        "hold": "",
        "pressure": False,
        "agent_running": False,
        "class": "error",
    }


def render_text(model):
    """The compact bar line: tæma ⟲2 ❄1 ↓3 9.3G."""
    if model.get("class") == "error":
        return "tæma error"
    segments = []
    if model.get("reviews"):
        segments.append("⟲%d" % model["reviews"])
    if model.get("frozen"):
        segments.append("❄%d" % model["frozen"])
    if model.get("deprioritized"):
        segments.append("↓%d" % model["deprioritized"])
    segments.append(format_memory(model.get("freed_today_bytes", 0)))
    return "tæma " + " ".join(segments)


def render_tooltip(model):
    """The multi-line state summary behind the bar line."""
    if model.get("class") == "error":
        return "tæma: daemon unreachable"
    lines = [
        "mode %s · profile %s" % (model.get("mode"), model.get("profile")),
        "%d reviews" % model.get("reviews", 0),
        "%d frozen" % model.get("frozen", 0),
        "%d deprioritized" % model.get("deprioritized", 0),
        "%s freed today" % format_memory(model.get("freed_today_bytes", 0)),
    ]
    if model.get("hold"):
        lines.append("held: %s" % model["hold"])
    if model.get("pressure"):
        lines.append("pressure: guard active")
    if not model.get("agent_running"):
        lines.append("agent not running")
    return "\n".join(lines)


def _short_text(model):
    if model.get("class") == "error":
        return "tæma !"
    if model.get("reviews"):
        return "tæma ⟲%d" % model["reviews"]
    if model.get("frozen"):
        return "tæma ❄%d" % model["frozen"]
    if model.get("deprioritized"):
        return "tæma ↓%d" % model["deprioritized"]
    return "tæma"


def render(format_name, model):
    """Render one bar line in a named format."""
    text, tooltip = render_text(model), render_tooltip(model)
    if format_name == "plain":
        return text
    if format_name == "waybar":
        return json.dumps(
            {"text": text, "tooltip": tooltip, "class": model.get("class", "ok")}
        )
    if format_name == "i3bar":
        return json.dumps(
            {
                "full_text": text,
                "short_text": _short_text(model),
                "color": CLASS_COLORS.get(model.get("class"), "#8a8a8a"),
                "urgent": model.get("class") == "error",
            }
        )
    if format_name == "json":
        payload = {"schema": "taema.bar.v1"}
        payload.update(model)
        payload["text"] = text
        payload["tooltip"] = tooltip
        return json.dumps(payload, sort_keys=True)
    raise ValueError("unknown bar format: %r" % (format_name,))
