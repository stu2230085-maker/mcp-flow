Failed to connect to user scope bus via local transport: Operation not permitted (consider using --machine=<user>@.host --user to connect to bus of other user)
import json
import os
import tempfile
import unittest
from pathlib import Path

from mcp_flow.cli import main
from mcp_flow.config_wrapper import unwrap_mcp_config, wrap_mcp_config


class ConfigWrapperTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "mcpServers": {
                "docs": {"command": "uvx", "args": ["docs-server", "--fast"], "env": {"K": "v"}},
                "mail": {"command": "node", "args": ["mail.js"]},
            },
            "other": True,
        }

    def test_wraps_commands_and_preserves_other_fields(self):
        wrapped = wrap_mcp_config(self.config, session_id="s1", db_path="trace.db", servers=["docs"])
        docs = wrapped["mcpServers"]["docs"]
        self.assertEqual(docs["command"], "python3")
        self.assertEqual(
            docs["args"],
            ["-m", "mcp_flow", "--db", "trace.db", "proxy", "--session", "s1",
             "--server", "docs", "--", "uvx", "docs-server", "--fast"],
        )
        self.assertEqual(docs["env"], {"K": "v"})
        self.assertEqual(wrapped["mcpServers"]["mail"], self.config["mcpServers"]["mail"])
        self.assertEqual(wrapped["other"], True)
        self.assertEqual(self.config["mcpServers"]["docs"]["command"], "uvx")

    def test_wrap_is_idempotent(self):
        wrapped = wrap_mcp_config(self.config, session_id="s1")
        self.assertEqual(wrap_mcp_config(wrapped, session_id="s2"), wrapped)

    def test_unwrap_restores_original(self):
        wrapped = wrap_mcp_config(self.config, session_id="s1", db_path="trace.db")
        self.assertEqual(unwrap_mcp_config(wrapped), self.config)

    def test_cli_creates_private_backup_and_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = json.dumps(self.config)
            path.write_text(original, encoding="utf-8")
            self.assertEqual(main(["wrap-config", str(path), "--session", "s1", "--dry-run"]), 0)
            self.assertEqual(path.read_text(encoding="utf-8"), original)
            self.assertEqual(main(["wrap-config", str(path), "--session", "s1"]), 0)
            backup = Path(str(path) + ".bak")
            self.assertEqual(backup.read_text(encoding="utf-8"), original)
            self.assertEqual(os.stat(backup).st_mode & 0o777, 0o600)
            self.assertEqual(main(["wrap-config", str(path), "--unwrap"]), 0)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), self.config)


if __name__ == "__main__":
    unittest.main()
