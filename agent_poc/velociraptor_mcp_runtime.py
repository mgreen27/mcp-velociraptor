"""
Shared MCP + Ollama runtime used by the Velociraptor agent.
"""
import json
import logging
import os
import sys
from collections.abc import Collection
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Optional

import ollama
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from velociraptor_env import load_environment

load_environment()

logger = logging.getLogger(__name__)
RUNTIME_VERBOSE = os.environ.get("VELOCIRAPTOR_AGENT_VERBOSE", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# The stdio client can emit noisy shutdown warnings when the child process has
# already exited before process-group cleanup runs. Keep the default runtime
# quiet unless the caller explicitly enables verbose diagnostics.
logging.getLogger("mcp.client.stdio").setLevel(logging.ERROR)
logging.getLogger("mcp.os.posix.utilities").setLevel(logging.ERROR)


class VelociraptorMCPClient:
    def __init__(
        self,
        model: Optional[str] = None,
        default_allowed_tools: Optional[Collection[str]] = None,
        verbose: Optional[bool] = None,
        label: Optional[str] = None,
    ):
        self.model = model or os.environ.get("OLLAMA_MODEL", "gemma4:e2b")
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.tools = []
        self.conversation_history = []
        self.verbose = RUNTIME_VERBOSE if verbose is None else verbose
        self.label = label or "MCP client"
        self.default_allowed_tools = (
            set(default_allowed_tools) if default_allowed_tools is not None else None
        )

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
        if self.verbose:
            print(
                f"{self.label} connected to Velociraptor MCP Bridge with {len(self.tools)} tools",
                file=sys.stderr,
            )

    async def disconnect(self):
        """Disconnect from the MCP server."""
        await self.exit_stack.aclose()

    def reset_conversation(self):
        """Clear prior chat state so each analysis can start with fresh context."""
        self.conversation_history = []

    def _resolve_allowed_tools(
        self,
        allowed_tools: Optional[Collection[str]] = None,
    ) -> Optional[set[str]]:
        if allowed_tools is not None:
            return set(allowed_tools)
        if self.default_allowed_tools is not None:
            return set(self.default_allowed_tools)
        return None

    def get_tool_definitions(
        self,
        allowed_tools: Optional[Collection[str]] = None,
    ) -> list[dict]:
        """Convert MCP tools to Ollama function calling format."""
        allowed_tool_names = self._resolve_allowed_tools(allowed_tools)
        tool_defs = []
        for tool in self.tools:
            if allowed_tool_names is not None and tool.name not in allowed_tool_names:
                continue
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
    def _decode_tool_payload(raw_text: str) -> dict:
        """Decode the bridge JSON envelope into a structured payload."""
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError:
            return {"ok": True, "data": raw_text}

        if not isinstance(payload, dict) or "ok" not in payload:
            return {"ok": True, "data": payload}

        return payload

    @classmethod
    def _decode_tool_output(cls, raw_text: str) -> str:
        """Unwrap the bridge's JSON envelope for agent consumers."""
        payload = cls._decode_tool_payload(raw_text)
        if not payload.get("ok", False):
            return f"Error calling tool: {payload.get('error', 'Unknown error')}"

        data = payload.get("data")
        if isinstance(data, (dict, list)):
            return json.dumps(data)
        if data is None:
            return "null"
        return str(data)

    async def call_tool_payload(self, tool_name: str, arguments: dict) -> dict:
        """Execute a tool via MCP and return the structured bridge payload."""
        try:
            result = await self.session.call_tool(tool_name, arguments)
            if result.content:
                raw_text = "\n".join(
                    item.text if hasattr(item, "text") else str(item)
                    for item in result.content
                )
                return self._decode_tool_payload(raw_text)
            return {"ok": True, "data": str(result)}
        except Exception as e:
            return {"ok": False, "error": f"Error calling tool {tool_name}: {str(e)}"}

    async def call_tool(self, tool_name: str, arguments: dict) -> str:
        """Execute a tool via MCP."""
        payload = await self.call_tool_payload(tool_name, arguments)
        if not payload.get("ok", False):
            return f"Error calling tool: {payload.get('error', 'Unknown error')}"

        data = payload.get("data")
        if isinstance(data, (dict, list)):
            return json.dumps(data)
        if data is None:
            return "null"
        return str(data)

    async def chat(
        self,
        user_message: str,
        allowed_tools: Optional[Collection[str]] = None,
        system_prompt: Optional[str] = None,
    ) -> str:
        """Send a message and get a response with tool calling."""
        if system_prompt and (
            not self.conversation_history
            or self.conversation_history[0].get("role") != "system"
        ):
            self.conversation_history.append({
                "role": "system",
                "content": system_prompt,
            })

        self.conversation_history.append({
            "role": "user",
            "content": user_message,
        })

        tools = self.get_tool_definitions(allowed_tools)
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

                if self.verbose:
                    print(f"{self.label} tool: {tool_name}", file=sys.stderr)
                    if tool_args:
                        print(json.dumps(tool_args, indent=2), file=sys.stderr)

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
