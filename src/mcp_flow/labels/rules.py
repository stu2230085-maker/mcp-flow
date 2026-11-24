"""Rule engine for assigning tool roles (source / sink / neutral) and confidentiality labels."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_flow.labels.detectors import detect_secrets_in_text
from mcp_flow.store.db import CallRow, FlowStore


@dataclass(frozen=True)
class ToolRoleRule:
    """Pattern rule matching `(server_pattern, tool_pattern)` to a role and optional default labels."""

    server_pattern: str
    tool_pattern: str
    role: str  # 'source' | 'sink' | 'neutral'
    labels: tuple[str, ...] = ()

    def matches(self, server_name: str, tool_name: str) -> bool:
        return fnmatch.fnmatchcase(server_name.casefold(), self.server_pattern.casefold()) and (
            fnmatch.fnmatchcase(tool_name.casefold(), self.tool_pattern.casefold())
        )


DEFAULT_TOOL_RULES: list[ToolRoleRule] = [
    # Sensitive / internal sources
    ToolRoleRule("vault*", "*", "source", ("confidential:vault",)),
    ToolRoleRule("secrets*", "*", "source", ("confidential:secret",)),
    ToolRoleRule("docs*", "*read*", "source", ("confidential:internal_doc",)),
    ToolRoleRule("docs*", "*get*", "source", ("confidential:internal_doc",)),
    ToolRoleRule("fs*", "*read*", "source", ("confidential:file",)),
    ToolRoleRule("db*", "*query*", "source", ("confidential:db",)),
    ToolRoleRule("*", "*get_secret*", "source", ("confidential:secret",)),
    ToolRoleRule("*", "*read_file*", "source", ("confidential:internal_doc",)),
    # External sinks (exfiltration channels)
    ToolRoleRule("mail*", "*send*", "sink", ()),
    ToolRoleRule("email*", "*send*", "sink", ()),
    ToolRoleRule("http*", "*post*", "sink", ()),
    ToolRoleRule("http*", "*put*", "sink", ()),
    ToolRoleRule("http*", "*request*", "sink", ()),
    ToolRoleRule("webhook*", "*", "sink", ()),
    ToolRoleRule("slack*", "*post*", "sink", ()),
    ToolRoleRule("*", "*send_mail*", "sink", ()),
    ToolRoleRule("*", "*send_email*", "sink", ()),
    ToolRoleRule("*", "*http_post*", "sink", ()),
    ToolRoleRule("*", "*upload*", "sink", ()),
    ToolRoleRule("*", "*write_external*", "sink", ()),
]


@dataclass
class LabelRuleEngine:
    """Evaluates tool roles and applies rule-based + content-based labels to a session."""

    rules: list[ToolRoleRule] = field(default_factory=lambda: list(DEFAULT_TOOL_RULES))

    @classmethod
    def from_json_file(cls, path: str | Path) -> LabelRuleEngine:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        rules: list[ToolRoleRule] = []
        for item in data.get("rules", []):
            rules.append(
                ToolRoleRule(
                    server_pattern=item.get("server", "*"),
                    tool_pattern=item.get("tool", "*"),
                    role=item.get("role", "neutral"),
                    labels=tuple(item.get("labels", [])),
                )
            )
        if data.get("include_defaults", True):
            rules.extend(DEFAULT_TOOL_RULES)
        return cls(rules=rules)

    def resolve_role_and_labels(
        self,
        server_name: str,
        tool_name: str,
        explicit_roles: dict[tuple[str, str], str] | None = None,
    ) -> tuple[str, list[str]]:
        """Determine the role ('source' | 'sink' | 'neutral') and labels for `(server_name, tool_name)`."""
        role: str | None = None
        if explicit_roles:
            role = explicit_roles.get((server_name, tool_name)) or explicit_roles.get(("*", tool_name))

        matched_labels: list[str] = []
        for rule in self.rules:
            if rule.matches(server_name, tool_name):
                if role is None:
                    role = rule.role
                for lbl in rule.labels:
                    if lbl not in matched_labels:
                        matched_labels.append(lbl)

        return (role or "neutral"), matched_labels

    def apply_to_session(self, store: FlowStore, session_id: str) -> dict[str, Any]:
        """
        Populate `tool_roles` and `labels` for all calls and fragments in `session_id`
        using configured pattern rules and regex content detectors.
        """
        explicit_roles = store.get_tool_roles()
        calls: list[CallRow] = store.get_calls(session_id)
        fragments = store.get_fragments(session_id)

        role_counts = {"source": 0, "sink": 0, "neutral": 0}
        labels_added = 0

        for call in calls:
            role, rule_labels = self.resolve_role_and_labels(
                call.server_name, call.tool, explicit_roles=explicit_roles
            )
            store.set_tool_role(call.server_name, call.tool, role)
            role_counts[role] = role_counts.get(role, 0) + 1
            for lbl in rule_labels:
                store.insert_label("call", call.id, lbl, source="rule")
                labels_added += 1

        for frag in fragments:
            detections = detect_secrets_in_text(frag.text)
            for det in detections:
                store.insert_label("fragment", frag.id, det.label, source=det.detector)
                # Also propagate content-detected label to the originating call when side == 'out'
                if frag.side == "out":
                    store.insert_label("call", frag.call_id, det.label, source=det.detector)
                labels_added += 1

        return {
            "role_counts": role_counts,
            "labels_added": labels_added,
        }
