from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from runtime.metadata import RuntimeMetadata, append_runtime_metadata, load_runtime_metadata


class RuntimeMetadataTests(unittest.TestCase):
    def test_append_and_load_jsonl_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "runtime.jsonl"
            record = RuntimeMetadata(
                run_id="run-demo",
                target_id="local-demo",
                source_commit="abc123",
                base_url="http://127.0.0.1:8080",
                health=True,
                readiness=True,
                gpu_worker="camp1",
                llm_endpoint_state="primary_healthy",
                reset_result=True,
                remaining_ports=[],
            )
            append_runtime_metadata(record, path)
            loaded = load_runtime_metadata(path)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].run_id, "run-demo")
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn("api_key", payload)

    def test_rejects_secret_bearing_url_and_invalid_slug(self) -> None:
        with self.assertRaises(ValueError):
            RuntimeMetadata(
                run_id="run/demo",
                target_id="local-demo",
                base_url="http://127.0.0.1:8080?token=secret",
                health=False,
                readiness=False,
            )


if __name__ == "__main__":
    unittest.main()
