import unittest
from types import SimpleNamespace

from agent_poc.velociraptor_mcp_runtime import VelociraptorMCPClient


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


if __name__ == "__main__":
    unittest.main()
