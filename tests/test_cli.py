"""Tests for CLI."""

import argparse
from unittest.mock import MagicMock, patch

from devai.cli import main


class TestCLI:
    def test_parser_has_commands(self):
        with patch("sys.argv", ["devai", "review", "--file", "test.py"]):
            with patch("devai.cli._get_client") as mock_client:
                mock_client.return_value.chat.return_value = MagicMock(content="Review done")
                with patch("devai.cli.read_file", return_value="code"):
                    main()

    def test_missing_command(self):
        with patch("sys.argv", ["devai"]):
            try:
                main()
            except SystemExit:
                pass
