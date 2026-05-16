"""
Shared MCP + Ollama runtime used by the Velociraptor agent.
"""
import json
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Optional

import ollama
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class VelociraptorMCPClient:
    def __init__(self, model: Optional[str] = None):
        self.model = model or os.environ.get("OLLAMA_MODEL", "gemma4:e2b")
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.tools = []
        self.conversation_history = []

    async def connect(self):
        """Connect to the MCP server bridge."""
        bridge_path = Path(__file__).resolve().parent.parent / "mcp_velociraptor_bridge.py"
        server_params = StdioServerParameters(
            command=sys.executable,
            args=[str(bridge_path)],
            env=None,
        )

        stdio_transport = await self.exit_stack.enter_async_context(
            stdio_client(server_params)
        )
        self.stdio, self.write = stdio_transport
        self.session = await self.exit_stack.enter_async_context(
            ClientSession(self.stdio, self.write)
        )

        await self.session.initialize()
        response = await self.session.list_tools()
        self.tools = response.tools
        print(f"Connected to Velociraptor MCP Bridge with {len(self.tools)} tools")

    async def disconnect(self):
        """Disconnect from the MCP server."""
        await self.exit_stack.aclose()

    def reset_conversation(self):
        """Clear prior chat state so each analysis can start with fresh context."""
        self.conversation_history = []

    def get_tool_definitions(self) -> list[dict]:
        """Convert MCP tools to Ollama function calling format."""
        tool_defs = []
        for tool in self.tools:
            tool_def = {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description or "",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "required": [],
                    },
                },
            }

            if tool.inputSchema:
                properties = tool.inputSchema.get("properties", {})
                required = tool.inputSchema.get("required", [])
                tool_def["function"]["parameters"]["properties"] = properties
                tool_def["function"]["parameters"]["required"] = required

            tool_defs.append(tool_def)
        return tool_defs

    @staticmethod
    def _decode_tool_output(raw_text: str) -> str:
        """Unwrap the bridge's JSON envelope for agent consumers."""
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError:
            return raw_text

        if not isinstance(payload, dict) or "ok" not in payload:
            return raw_text

        if not payload.get("ok", False):
            return f"Error calling tool: {payload.get('error', 'Unknown error')}"

        data = payload.get("data")
        if isinstance(data, (dict, list)):
            return json.dumps(data)
        if data is None:
            return "null"
        return str(data)

    async def call_tool(self, tool_name: str, arguments: dict) -> str:
        """Execute a tool via MCP."""
        try:
            result = await self.session.call_tool(tool_name, arguments)
            if result.content:
                raw_text = "\n".join(
                    item.text if hasattr(item, "text") else str(item)
                    for item in result.content
                )
                return self._decode_tool_output(raw_text)
            return str(result)
        except Exception as e:
            return f"Error calling tool {tool_name}: {str(e)}"

    async def chat(self, user_message: str) -> str:
        """Send a message and get a response with tool calling."""
        self.conversation_history.append({
            "role": "user",
            "content": user_message,
        })

        tools = self.get_tool_definitions()
        response = ollama.chat(
            model=self.model,
            messages=self.conversation_history,
            tools=tools,
        )

        while response.get("message", {}).get("tool_calls"):
            self.conversation_history.append(response["message"])

            for tool_call in response["message"]["tool_calls"]:
                tool_name = tool_call["function"]["name"]
                tool_args = tool_call["function"]["arguments"]

                print(f"\nTool: {tool_name}")
                if tool_args:
                    print(json.dumps(tool_args, indent=2))

                tool_result = await self.call_tool(tool_name, tool_args)
                self.conversation_history.append({
                    "role": "tool",
                    "content": tool_result,
                })

            response = ollama.chat(
                model=self.model,
                messages=self.conversation_history,
                tools=tools,
            )

        assistant_message = response["message"]["content"]
        self.conversation_history.append({
            "role": "assistant",
            "content": assistant_message,
        })
        return assistant_message
