Failed to connect to user scope bus via local transport: Operation not permitted (consider using --machine=<user>@.host --user to connect to bus of other user)
"""Transform MCP client JSON configuration files for the stdio proxy."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable


def _is_wrapped(entry: dict[str, Any]) -> bool:
    command = entry.get("command")
    args = entry.get("args", [])
    return (
        isinstance(command, str)
        and isinstance(args, list)
        and "-m" in args
        and args.index("-m") + 1 < len(args)
        and args[args.index("-m") + 1] == "mcp_flow"
        and "proxy" in args
        and "--" in args
    )


def _unwrap_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Return the original command and args from a wrapper generated here."""
    args = entry.get("args", [])
    try:
        marker = args.index("--")
    except (AttributeError, ValueError):
        return entry
    # The command after the delimiter is encoded as the first arg, since the
    # wrapper executable itself is the configured command.
    original = args[marker + 1 :]
    if not original:
        return entry
    entry["command"] = original[0]
    entry["args"] = original[1:]
    return entry


def wrap_mcp_config(
    config: dict[str, Any],
    *,
    session_id: str,
    db_path: str = "mcp_flow.db",
    servers: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Return a copy of *config* with selected MCP servers wrapped.

    Entries already invoking ``mcp_flow proxy`` are left unchanged.
    """
    result = deepcopy(config)
    mcp_servers = result.get("mcpServers")
    if not isinstance(mcp_servers, dict):
        raise ValueError('Configuration must contain an "mcpServers" object')
    selected = set(servers) if servers is not None else None
    unknown = selected.difference(mcp_servers) if selected is not None else set()
    if unknown:
        raise ValueError("Unknown MCP server(s): " + ", ".join(sorted(unknown)))

    for name, entry in mcp_servers.items():
        if selected is not None and name not in selected:
            continue
        if not isinstance(entry, dict):
            raise ValueError(f'Configuration for server "{name}" must be an object')
        if _is_wrapped(entry):
            continue
        command = entry.get("command")
        args = entry.get("args", [])
        if not isinstance(command, str) or not command:
            raise ValueError(f'Server "{name}" must have a non-empty command')
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ValueError(f'Server "{name}" args must be a list of strings')
        entry["command"] = "python3"
        entry["args"] = [
            "-m", "mcp_flow", "--db", db_path, "proxy",
            "--session", session_id, "--server", name, "--", command, *args,
        ]
    return result


def unwrap_mcp_config(
    config: dict[str, Any], *, servers: Iterable[str] | None = None
) -> dict[str, Any]:
    """Return a copy of *config* with selected generated wrappers removed."""
    result = deepcopy(config)
    mcp_servers = result.get("mcpServers")
    if not isinstance(mcp_servers, dict):
        raise ValueError('Configuration must contain an "mcpServers" object')
    selected = set(servers) if servers is not None else None
    unknown = selected.difference(mcp_servers) if selected is not None else set()
    if unknown:
        raise ValueError("Unknown MCP server(s): " + ", ".join(sorted(unknown)))
    for name, entry in mcp_servers.items():
        if selected is not None and name not in selected:
            continue
        if not isinstance(entry, dict):
            raise ValueError(f'Configuration for server "{name}" must be an object')
        if _is_wrapped(entry):
            _unwrap_entry(entry)
    return result
