import json
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO

from agent_poc.mcp_agent import (
    ANALYSIS_ROLE_PROFILES,
    LINUX_TOOLSETS,
    MACOS_TOOLSETS,
    WINDOWS_TOOLSETS,
    CaseContext,
    VelociraptorAgent,
    format_results_text,
)


class FakeTool:
    def __init__(self, name: str):
        self.name = name
        self.description = ""
        self.inputSchema = {
            "type": "object",
            "properties": {},
            "required": [],
        }


class FakeClient:
    def __init__(
        self,
        factory,
        model=None,
        default_allowed_tools=None,
        verbose=None,
        label=None,
    ):
        self.factory = factory
        self.model = model
        self.verbose = verbose
        self.label = label
        self.default_allowed_tools = (
            set(default_allowed_tools) if default_allowed_tools is not None else None
        )
        self.tools = [FakeTool(name) for name in factory.tool_names]
        self.conversation_history = []
        self.call_tool_calls = []
        self.chat_calls = []
        self.connected = False
        factory.instances.append(self)

    async def connect(self):
        self.connected = True

    async def disconnect(self):
        self.connected = False

    def reset_conversation(self):
        self.conversation_history = []

    async def call_tool(self, tool_name, arguments):
        payload = await self.call_tool_payload(tool_name, arguments)
        if not payload.get("ok", False):
            return f"Error calling tool: {payload.get('error')}"
        return json.dumps(payload.get("data"))

    async def call_tool_payload(self, tool_name, arguments):
        self.call_tool_calls.append((tool_name, arguments))
        if tool_name == "client_info":
            self.factory.client_info_call_count += 1
            if arguments.get("hostname") == self.factory.hostname:
                return {"ok": True, "data": self.factory.client_info}
            if arguments.get("search_all_orgs"):
                return {"ok": True, "data": self.factory.client_info}
            return {"ok": False, "error": "Client not found"}

        if tool_name in self.factory.tool_payloads:
            payload = self.factory.tool_payloads[tool_name]
            if isinstance(payload, dict) and "ok" in payload:
                return payload
            return {"ok": True, "data": payload}
        if tool_name in self.factory.tool_names:
            return {"ok": True, "data": []}

        raise AssertionError(f"Unexpected tool call: {tool_name}")

    async def chat(self, user_message, allowed_tools=None, system_prompt=None):
        allowed = tuple(sorted(allowed_tools or self.default_allowed_tools or []))
        self.chat_calls.append({
            "user_message": user_message,
            "allowed_tools": list(allowed),
            "system_prompt": system_prompt,
        })

        if self.default_allowed_tools is None and allowed == tuple():
            if self.factory.manager_response is not None:
                return self.factory.manager_response(user_message)
            return f"manager summary: {user_message}"

        analyst_key = tuple(sorted(self.default_allowed_tools or allowed))
        if analyst_key in self.factory.failures:
            raise RuntimeError(self.factory.failures[analyst_key])

        return self.factory.analyst_responses.get(
            analyst_key,
            f"analysis for {','.join(analyst_key)}",
        )


class FakeClientFactory:
    def __init__(
        self,
        hostname="RE-DEV",
        os_type="Windows",
        analyst_responses=None,
        manager_response=None,
        failures=None,
        tool_payloads=None,
    ):
        self.hostname = hostname
        self.client_info = {
            "client_id": "C.1234",
            "Hostname": hostname,
            "OSType": os_type,
        }
        self.instances = []
        self.client_info_call_count = 0
        self.analyst_responses = analyst_responses or {}
        self.manager_response = manager_response
        self.failures = failures or {}
        self.tool_payloads = tool_payloads or self._default_tool_payloads(os_type)
        all_tools = set()
        for toolset in WINDOWS_TOOLSETS.values():
            all_tools.update(toolset)
        for toolset in LINUX_TOOLSETS.values():
            all_tools.update(toolset)
        for toolset in MACOS_TOOLSETS.values():
            all_tools.update(toolset)
        self.tool_names = sorted(all_tools | {"client_info"})

    def __call__(
        self,
        model=None,
        default_allowed_tools=None,
        verbose=None,
        label=None,
    ):
        return FakeClient(
            self,
            model=model,
            default_allowed_tools=default_allowed_tools,
            verbose=verbose,
            label=label,
        )

    @staticmethod
    def _default_tool_payloads(os_type):
        if os_type.lower() == "linux":
            return {
                "linux_pslist": [{"Pid": 1, "Name": "systemd", "CommandLine": "/sbin/init"}],
                "linux_netstat_enriched": [{"Name": "sshd", "Status": "LISTEN", "Lport": 22}],
            }

        return {
            "windows_pslist": [
                {
                    "Pid": 4000,
                    "Name": "GruntHTTP.exe",
                    "Exe": "C:\\Users\\yolo\\Desktop\\GruntHTTP.exe",
                    "CommandLine": "GruntHTTP.exe --beacon",
                    "Username": "RE-DEV\\yolo",
                    "Authenticode.Trusted": "untrusted",
                }
            ],
            "windows_netstat_enriched": [
                {
                    "Name": "Velociraptor.exe",
                    "Status": "ESTABLISHED",
                    "Raddr": "61.68.76.228",
                    "Rport": 443,
                    "Path": "C:\\Program Files\\Velociraptor\\Velociraptor.exe",
                }
            ],
            "windows_scheduled_tasks": [
                {
                    "OSPath": "C:\\Windows\\System32\\Tasks\\Internet Detector",
                    "Command": "c:\\tools\\internet_detector\\internet_detector.exe",
                    "UserId": "RE-DEV\\yolo",
                }
            ],
            "windows_services": [
                {
                    "Name": "WdNisSvc",
                    "DisplayName": "Microsoft Defender Antivirus Network Inspection Service",
                    "State": "Running",
                    "AbsoluteExePath": "C:\\Program Files\\Windows Defender\\NisSrv.exe",
                }
            ],
            "windows_execution_amcache": [
                {
                    "FullPath": "C:\\Users\\yolo\\Desktop\\GruntHTTP.exe",
                    "Publisher": "unknown",
                    "SHA1": "deadbeef",
                }
            ],
            "windows_execution_prefetch": [
                {
                    "Binary": "\\VOLUME{GUID}\\USERS\\YOLO\\DESKTOP\\GRUNTHTTP.EXE",
                    "RunCount": 3,
                }
            ],
            "windows_execution_shimcache": [
                {
                    "Path": "C:\\Users\\yolo\\Desktop\\GruntHTTP.exe",
                    "ExecutionFlag": "True",
                }
            ],
            "windows_execution_userassist": [
                {
                    "Name": "GruntHTTP.exe",
                    "User": "RE-DEV\\yolo",
                }
            ],
            "windows_execution_bam": [
                {
                    "Name": "C:\\Users\\yolo\\Desktop\\GruntHTTP.exe",
                }
            ],
            "windows_evidence_of_download": [
                {
                    "DownloadedFilePath": "C:\\Users\\yolo\\Desktop\\GruntHTTP.exe",
                    "HostUrl": "https://example.test/grunthttp.exe",
                }
            ],
        }


class VelociraptorAgentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _build_agent(self, factory):
        return VelociraptorAgent(
            model="fake-model",
            output_dir=self.temp_dir.name,
            client_factory=factory,
        )

    async def test_manager_selects_analysts_by_os(self):
        factory = FakeClientFactory()
        agent = self._build_agent(factory)

        windows_context = CaseContext(
            hostname="WIN",
            client_id="C.win",
            org_id=None,
            os_type="Windows",
            target="windows client C.win",
            platform_guidance="Windows only",
            shared_guidance="shared",
        )
        linux_context = CaseContext(
            hostname="LINUX",
            client_id="C.linux",
            org_id=None,
            os_type="Linux",
            target="linux client C.linux",
            platform_guidance="Linux only",
            shared_guidance="shared",
        )
        macos_context = CaseContext(
            hostname="MAC",
            client_id="C.mac",
            org_id=None,
            os_type="Darwin",
            target="macos client C.mac",
            platform_guidance="macOS only",
            shared_guidance="shared",
        )

        windows_specs, windows_skipped = agent._select_analysts(windows_context)
        linux_specs, linux_skipped = agent._select_analysts(linux_context)
        macos_specs, macos_skipped = agent._select_analysts(macos_context)

        self.assertEqual([spec.role for spec in windows_specs], list(WINDOWS_TOOLSETS.keys()))
        self.assertEqual(windows_skipped, [])
        self.assertEqual([spec.role for spec in linux_specs], list(LINUX_TOOLSETS.keys()))
        self.assertEqual(linux_skipped, [])
        self.assertEqual([spec.role for spec in macos_specs], list(MACOS_TOOLSETS.keys()))
        self.assertEqual(macos_skipped, [])

    async def test_engagement_uses_one_client_per_analyst(self):
        engagement_roles = ANALYSIS_ROLE_PROFILES["engagement"]
        responses = {
            tuple(sorted(tools)): f"{role} finding"
            for role, tools in WINDOWS_TOOLSETS.items()
        }
        factory = FakeClientFactory(
            analyst_responses=responses,
            manager_response=lambda prompt: "manager summary",
        )
        agent = self._build_agent(factory)
        await agent.initialize()
        try:
            result = await agent.analyze_endpoint("RE-DEV", "engagement")
        finally:
            await agent.shutdown()

        analyst_instances = [
            client for client in factory.instances if client.default_allowed_tools is not None
        ]
        self.assertEqual(len(factory.instances), 1 + len(engagement_roles))
        self.assertEqual(len(analyst_instances), len(engagement_roles))
        self.assertEqual(
            {tuple(sorted(client.default_allowed_tools)) for client in analyst_instances},
            {tuple(sorted(WINDOWS_TOOLSETS[role])) for role in engagement_roles},
        )
        self.assertEqual(factory.instances[0].label, "management agent")
        self.assertEqual(
            sorted(client.label for client in analyst_instances),
            sorted(f"{role} analyst" for role in engagement_roles),
        )
        self.assertEqual(sorted(result["analysts"].keys()), sorted(engagement_roles))

    async def test_partial_analyst_failure_does_not_abort(self):
        factory = FakeClientFactory(
            analyst_responses={
                tuple(sorted(WINDOWS_TOOLSETS["process"])): "process finding",
                tuple(sorted(WINDOWS_TOOLSETS["persistence"])): "persistence finding",
                tuple(sorted(WINDOWS_TOOLSETS["execution"])): "execution finding",
            },
            manager_response=lambda prompt: "manager summary",
            failures={tuple(sorted(WINDOWS_TOOLSETS["network"])): "network failed"},
        )
        agent = self._build_agent(factory)
        await agent.initialize()
        try:
            result = await agent.analyze_endpoint("RE-DEV", "engagement")
        finally:
            await agent.shutdown()

        self.assertEqual(result["analysts"]["network"]["status"], "error")
        self.assertEqual(result["analysts"]["process"]["status"], "completed")
        self.assertIn(
            {"role": "network", "message": "network failed"},
            result["errors"],
        )
        self.assertIn("tool_results", result["analysts"]["network"]["evidence"])
        self.assertEqual(result["manager_summary"], "manager summary")

    async def test_full_alias_uses_engagement_workflow(self):
        factory = FakeClientFactory(
            manager_response=lambda prompt: "manager summary",
        )
        agent = self._build_agent(factory)
        await agent.initialize()
        try:
            result = await agent.analyze_endpoint("RE-DEV", "full")
        finally:
            await agent.shutdown()

        self.assertEqual(result["workflow"], "engagement")

    async def test_manager_resolves_client_info_once_and_reuses_it(self):
        factory = FakeClientFactory(manager_response=lambda prompt: "manager summary")
        agent = self._build_agent(factory)
        await agent.initialize()
        try:
            await agent.analyze_endpoint("RE-DEV", "engagement")
        finally:
            await agent.shutdown()

        self.assertEqual(factory.client_info_call_count, 1)

    async def test_analysts_receive_filtered_tool_allowlists(self):
        engagement_roles = ANALYSIS_ROLE_PROFILES["engagement"]
        factory = FakeClientFactory(manager_response=lambda prompt: "manager summary")
        agent = self._build_agent(factory)
        await agent.initialize()
        try:
            await agent.analyze_endpoint("RE-DEV", "engagement")
        finally:
            await agent.shutdown()

        analyst_tool_calls = [
            tool_name
            for client in factory.instances
            if client.default_allowed_tools is not None
            for tool_name, _arguments in client.call_tool_calls
            if tool_name != "client_info"
        ]
        self.assertEqual(
            set(analyst_tool_calls),
            {
                tool
                for role in engagement_roles
                for tool in WINDOWS_TOOLSETS[role]
            },
        )

    async def test_execution_workflow_only_uses_execution_tools(self):
        factory = FakeClientFactory(manager_response=lambda prompt: "manager summary")
        agent = self._build_agent(factory)
        await agent.initialize()
        try:
            result = await agent.analyze_endpoint("RE-DEV", "execution")
        finally:
            await agent.shutdown()

        analyst_tool_calls = [
            tool_name
            for client in factory.instances
            if client.default_allowed_tools is not None
            for tool_name, _arguments in client.call_tool_calls
            if tool_name != "client_info"
        ]
        self.assertEqual(set(analyst_tool_calls), set(WINDOWS_TOOLSETS["execution"]))
        self.assertEqual(sorted(result["analysts"].keys()), ["execution"])

    async def test_deep_profile_uses_all_defined_windows_roles(self):
        factory = FakeClientFactory(manager_response=lambda prompt: "manager summary")
        agent = self._build_agent(factory)
        await agent.initialize()
        try:
            result = await agent.analyze_endpoint("RE-DEV", "deep")
        finally:
            await agent.shutdown()

        self.assertEqual(sorted(result["analysts"].keys()), sorted(WINDOWS_TOOLSETS))

    async def test_analyst_results_include_compact_evidence(self):
        factory = FakeClientFactory(manager_response=lambda prompt: "manager summary")
        agent = self._build_agent(factory)
        await agent.initialize()
        try:
            result = await agent.analyze_endpoint("RE-DEV", "execution")
        finally:
            await agent.shutdown()

        execution = result["analysts"]["execution"]
        self.assertIn("evidence", execution)
        self.assertIn("tool_results", execution["evidence"])
        self.assertTrue(execution["evidence"]["tool_results"]["windows_execution_amcache"]["ok"])

    async def test_manager_synthesis_uses_analyst_outputs(self):
        factory = FakeClientFactory(
            analyst_responses={
                tuple(sorted(tools)): f"{role} finding"
                for role, tools in WINDOWS_TOOLSETS.items()
            },
            manager_response=lambda prompt: prompt,
        )
        agent = self._build_agent(factory)
        await agent.initialize()
        try:
            result = await agent.analyze_endpoint("RE-DEV", "engagement")
        finally:
            await agent.shutdown()

        manager_client = factory.instances[0]
        manager_prompt = manager_client.chat_calls[0]["user_message"]
        self.assertIn("process finding", manager_prompt)
        self.assertIn("network finding", manager_prompt)
        self.assertIn("user_activity finding", manager_prompt)
        self.assertIn("system_inventory finding", manager_prompt)
        self.assertNotIn("filesystem finding", manager_prompt)
        self.assertNotIn("security finding", manager_prompt)
        self.assertNotIn("Analyze running processes on", manager_prompt)
        self.assertEqual(result["manager_summary"], manager_prompt)

    async def test_text_output_places_manager_summary_before_analysts(self):
        factory = FakeClientFactory(manager_response=lambda prompt: "final summary")
        agent = self._build_agent(factory)
        await agent.initialize()
        try:
            result = await agent.analyze_endpoint("RE-DEV", "triage")
        finally:
            await agent.shutdown()

        rendered = format_results_text(result)
        self.assertLess(rendered.index("Manager Summary:"), rendered.index("Analysts:"))
        self.assertIn("[process]", rendered)
        self.assertIn("[network]", rendered)

    async def test_verbose_mode_prints_collection_progress(self):
        factory = FakeClientFactory(manager_response=lambda prompt: "manager summary")
        agent = VelociraptorAgent(
            model="fake-model",
            output_dir=self.temp_dir.name,
            client_factory=factory,
            verbose=True,
        )
        stderr = StringIO()
        with redirect_stderr(stderr):
            await agent.initialize()
            try:
                await agent.analyze_endpoint("RE-DEV", "execution")
            finally:
                await agent.shutdown()

        output = stderr.getvalue()
        self.assertIn("execution analyst running Windows.Detection.Amcache", output)
        self.assertIn("execution analyst running Windows.Forensics.Prefetch", output)
        self.assertIn("execution analyst summarizing evidence from 7 collections", output)


if __name__ == "__main__":
    unittest.main()
