import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agent_poc.velociraptor_mcp_runtime import (
    VelociraptorMCPClient,
    _azure_openai_base_url,
    _default_model,
    _model_provider,
)


class VelociraptorMCPClientRuntimeTests(unittest.TestCase):
    def test_get_tool_definitions_filters_allowlisted_tools(self):
        client = VelociraptorMCPClient(model="fake-model")
        client.tools = [
            SimpleNamespace(
                name="windows_pslist",
                description="processes",
                inputSchema={"properties": {"client_id": {"type": "string"}}, "required": ["client_id"]},
            ),
            SimpleNamespace(
                name="windows_netstat_enriched",
                description="network",
                inputSchema={"properties": {"client_id": {"type": "string"}}, "required": ["client_id"]},
            ),
        ]

        filtered = client.get_tool_definitions({"windows_pslist"})

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["function"]["name"], "windows_pslist")

    def test_decode_tool_payload_preserves_bridge_envelope(self):
        payload = VelociraptorMCPClient._decode_tool_payload(
            '{"ok": true, "data": {"client_id": "C.1234"}}'
        )
        self.assertEqual(payload, {"ok": True, "data": {"client_id": "C.1234"}})

    def test_model_provider_defaults_to_ollama(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(_model_provider(), "ollama")
            self.assertEqual(_default_model("ollama"), "gemma4:e2b")

    def test_azure_provider_uses_azure_model_default(self):
        with patch.dict("os.environ", {"VELOCIRAPTOR_MODEL_PROVIDER": "azure"}, clear=True):
            client = VelociraptorMCPClient()
            self.assertEqual(client.model_provider, "azure")
            self.assertEqual(client.model, "gpt-5.4-mini")

    def test_azure_base_url_appends_openai_v1(self):
        with patch.dict(
            "os.environ",
            {"AZURE_OPENAI_ENDPOINT": "https://example-resource.openai.azure.com"},
            clear=True,
        ):
            self.assertEqual(
                _azure_openai_base_url(),
                "https://example-resource.openai.azure.com/openai/v1/",
            )


if __name__ == "__main__":
    unittest.main()
