# SPDX-License-Identifier: AGPL-3.0-or-later

import os
from pathlib import Path
import tempfile
from unittest import TestCase
from unittest.mock import patch

import yaml

from searx import server_config, settings, settings_loader
from searx import search as searx_search


class FakeForm(dict):
    def getlist(self, key):
        value = self.get(key, [])
        return value if isinstance(value, list) else [value]


class ServerConfigTests(TestCase):

    def test_runtime_file_is_merged_after_main_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            main_path = Path(temporary) / "settings.yml"
            runtime_path = Path(temporary) / "runtime.yml"
            main_path.write_text(
                "use_default_settings: true\noutgoing:\n  request_timeout: 9\n",
                encoding="utf-8",
            )
            runtime_path.write_text(
                "outgoing:\n  proxy_pool:\n    enabled: true\n    max_attempts: 2\n    entries:\n      - http://proxy.test:8080\n",
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                {
                    "SEARXNG_SETTINGS_PATH": str(main_path),
                    "SEARXNG_RUNTIME_SETTINGS_PATH": str(runtime_path),
                },
            ):
                loaded, message = settings_loader.load_settings()

            self.assertEqual(9, loaded["outgoing"]["request_timeout"])
            self.assertTrue(loaded["outgoing"]["proxy_pool"]["enabled"])
            self.assertIn("merge runtime settings", message)

    def test_save_persists_engine_and_proxy_pool_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "settings.yml"
            path.write_text(
                "use_default_settings: true\nserver:\n  secret_key: keep-me\nengines:\n  - name: baidu\n    timeout: 8\n",
                encoding="utf-8",
            )
            effective = {
                "engines": [
                    {"name": "baidu", "disabled": False},
                    {"name": "google browser", "disabled": True, "inactive": True},
                ],
                "outgoing": {"proxy_pool": {}},
                "browser_search": {"enabled": False},
                "general": {"enable_metrics": True},
            }
            form = FakeForm(
                {
                    "server_engine__0": "google browser",
                    "http_proxy_pool_enabled": "on",
                    "http_proxy_pool_max_attempts": "3",
                    "http_proxy_pool_entries": "socks5://user:pass@proxy.test:1080\ninvalid",
                }
            )

            with (
                patch.dict(settings, effective, clear=True),
                patch.dict(os.environ, {"SEARXNG_RUNTIME_SETTINGS_PATH": str(path)}),
                patch.object(searx_search, "initialize") as initialize,
            ):
                result = server_config.save(form)

            saved = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual("keep-me", saved["server"]["secret_key"])
            self.assertEqual(
                [
                    {"name": "baidu", "timeout": 8, "disabled": True},
                    {"name": "google browser", "disabled": False},
                ],
                saved["engines"],
            )
            self.assertEqual(
                ["socks5://user:pass@proxy.test:1080"],
                saved["outgoing"]["proxy_pool"]["entries"],
            )
            self.assertTrue(result["proxy_pool"]["enabled"])
            self.assertFalse(result["engines"][1]["inactive"])
            initialize.assert_called_once()
