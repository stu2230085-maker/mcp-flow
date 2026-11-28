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
        if not isinstance(data, dict):
            raise ValueError("Rules JSON root must be an object")
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError('Rules JSON "rules" field must be a list')
        include_defaults = data.get("include_defaults", True)
        if not isinstance(include_defaults, bool):
            raise ValueError('Rules JSON "include_defaults" field must be a boolean')

        rules: list[ToolRoleRule] = []
        for idx, item in enumerate(raw_rules):
            if not isinstance(item, dict):
                raise ValueError(f"Rule at index {idx} must be an object")
            server_pat = item.get("server", "*")
            tool_pat = item.get("tool", "*")
            role = item.get("role", "neutral")
            raw_labels = item.get("labels", [])
            if not isinstance(server_pat, str) or not isinstance(tool_pat, str):
                raise ValueError(f"Rule at index {idx}: 'server' and 'tool' must be strings")
            if role not in ("source", "sink", "neutral"):
                raise ValueError(
                    f"Rule at index {idx}: invalid role {role!r} (expected 'source', 'sink', or 'neutral')"
                )
            if not isinstance(raw_labels, list) or not all(isinstance(lbl, str) for lbl in raw_labels):
                raise ValueError(f"Rule at index {idx}: 'labels' must be a list of strings")
            rules.append(
                ToolRoleRule(
                    server_pattern=server_pat,
                    tool_pattern=tool_pat,
                    role=role,
                    labels=tuple(raw_labels),
                )
            )
        if include_defaults:
            rules.extend(DEFAULT_TOOL_RULES)
        return cls(rules=rules)

    def resolve_role_and_labels(
        self,
        server_name: str,
        tool_name: str,
        explicit_roles: dict[tuple[str, str], str] | None = None,
        prefer_rules: bool = False,
    ) -> tuple[str, list[str]]:
        """Determine the role ('source' | 'sink' | 'neutral') and labels for `(server_name, tool_name)`."""
        explicit_role: str | None = None
        if explicit_roles:
            explicit_role = explicit_roles.get((server_name, tool_name)) or explicit_roles.get(
                ("*", tool_name)
            )

        rule_role: str | None = None
        matched_labels: list[str] = []
        for rule in self.rules:
            if rule.matches(server_name, tool_name):
                if rule_role is None:
                    rule_role = rule.role
                for lbl in rule.labels:
                    if lbl not in matched_labels:
                        matched_labels.append(lbl)

        if prefer_rules:
            role = rule_role or explicit_role or "neutral"
        else:
            role = explicit_role or rule_role or "neutral"
        return role, matched_labels

    def apply_to_session(
        self,
        store: FlowStore,
        session_id: str,
        persist_labels: bool = False,
        prefer_rules: bool = False,
    ) -> dict[str, Any]:
        """
        Populate `tool_roles` and `labels` for all calls and fragments in `session_id`
        using configured pattern rules and regex content detectors.

        When `persist_labels=True`, sensitive `out` fragments (`secret:*`, `confidential:*`)
        are also registered in `persistent_fingerprints` (hash-only, no plaintext).
        When `prefer_rules=True`, configured rules take precedence over previously stored `tool_roles`.
        """
        explicit_roles = store.get_tool_roles()
        calls: list[CallRow] = store.get_calls(session_id)
        fragments = store.get_fragments(session_id)

        role_counts = {"source": 0, "sink": 0, "neutral": 0}
        labels_added = 0

        for call in calls:
            role, rule_labels = self.resolve_role_and_labels(
                call.server_name,
                call.tool,
                explicit_roles=explicit_roles,
                prefer_rules=prefer_rules,
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

        persisted_count = 0
        if persist_labels:
            from mcp_flow.match.cross_session import register_persistent_fingerprints

            persisted = register_persistent_fingerprints(store, session_id)
            persisted_count = len(persisted)

        return {
            "role_counts": role_counts,
            "labels_added": labels_added,
            "persisted_fingerprints": persisted_count,
        }
