"""CLI entry point for `python -m mcp_flow`."""

from __future__ import annotations

import sys

from mcp_flow.cli import main

if __name__ == "__main__":
    sys.exit(main())
