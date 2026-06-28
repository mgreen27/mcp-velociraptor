"""
Headless Agent for Automated Velociraptor DFIR Analysis
"""
import argparse
import asyncio
import ipaddress
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from .velociraptor_mcp_runtime import VelociraptorMCPClient, _default_model, _model_provider
except ImportError:
    from velociraptor_mcp_runtime import VelociraptorMCPClient, _default_model, _model_provider


ANALYST_SYSTEM_PROMPT = (
    "You are a DFIR analyst working inside a bounded investigation role. "
    "You will receive a pre-collected evidence bundle and must summarize only "
    "that evidence. Base conclusions on the provided evidence, do not invent "
    "evidence, clearly call out uncertainty, and do not ask the user for more "
    "input. Finish with a self-contained assessment."
)

MANAGER_SYSTEM_PROMPT = (
    "You are the engagement manager for a DFIR investigation. Synthesize the "
    "analyst findings into a concise case summary. Do not invent evidence, and "
    "separate likely benign analyst/lab activity from likely malicious behavior "
    "when the evidence supports that distinction."
)

DEFAULT_SHARED_GUIDANCE = (
    "Treat this endpoint as a potential production endpoint unless the case "
    "context or collected evidence indicates it is a lab, analyst workstation, "
    "or malware analysis host."
)

WINDOWS_TOOL_REQUESTS = {
    "process": (
        ("windows_pslist", {}),
    ),
    "network": (
        ("windows_netstat_enriched", {}),
        ("windows_dns_cache", {}),
    ),
    "persistence": (
        (
            "windows_scheduled_tasks",
            {"Fields": "OSPath,Mtime,Command,Arguments,UserId,StartBoundary,Authenticode"},
        ),
        (
            "windows_services",
            {
                "Fields": (
                    "Name,DisplayName,StartType,State,AbsoluteExePath,"
                    "UserAccount,Created,CertinfoServiceExe"
                )
            },
        ),
        ("windows_autoruns", {}),
        ("windows_wmi_persistence", {}),
    ),
    "execution": (
        ("windows_execution_amcache", {}),
        ("windows_execution_prefetch", {}),
        ("windows_execution_shimcache", {}),
        ("windows_execution_userassist", {}),
        ("windows_execution_bam", {}),
        ("windows_execution_activitiesCache", {}),
        ("windows_evidence_of_download", {}),
    ),
    "user_activity": (
        ("windows_recentdocs", {}),
        ("windows_shellbags", {}),
        ("windows_logon_events", {}),
        ("windows_rdp_sessions", {}),
        ("windows_powershell_history", {}),
        ("windows_powershell_scriptblock", {}),
        ("windows_browser_history", {}),
    ),
    "system_inventory": (
        ("windows_mounted_mass_storage_usb", {}),
        ("windows_mountpoints2", {}),
        ("windows_shadow_copies", {}),
    ),
    "filesystem": (
        ("windows_recycle_bin", {}),
        ("windows_ntfs_mft", {}),
        ("windows_ntfs_mft_search", {}),
        ("windows_usn_journal", {}),
        ("windows_srum", {}),
        ("windows_timestomp", {}),
    ),
    "security": (
        ("windows_event_logs", {}),
        ("windows_event_log_cleared", {}),
        ("windows_malfind", {}),
        ("windows_mutants", {}),
    ),
}

WINDOWS_TOOLSETS = {
    role: tuple(tool_name for tool_name, _ in requests)
    for role, requests in WINDOWS_TOOL_REQUESTS.items()
}

LINUX_TOOL_REQUESTS = {
    "process": (
        ("linux_pslist", {}),
    ),
    "network": (
        ("linux_netstat_enriched", {}),
        ("linux_arp_cache", {}),
    ),
    "persistence": (
        ("linux_crontab", {}),
        ("linux_services", {}),
        ("linux_ssh_authorized_keys", {}),
    ),
    "user_activity": (
        ("linux_bash_history", {}),
        ("linux_ssh_logins", {}),
        ("linux_last_user_login", {}),
    ),
    "system_inventory": (
        ("linux_users", {}),
        ("linux_groups", {}),
        ("linux_mounts", {}),
    ),
    "security": (
        ("linux_journal_logs", {}),
    ),
    "filesystem": (
        ("linux_file_finder", {"SearchFilesGlob": "/home/*/Downloads/**"}),
    ),
}

LINUX_TOOLSETS = {
    role: tuple(tool_name for tool_name, _ in requests)
    for role, requests in LINUX_TOOL_REQUESTS.items()
}

MACOS_TOOL_REQUESTS = {
    "process": (
        ("macos_pslist", {}),
    ),
    "network": (
        ("macos_netstat", {}),
    ),
    "persistence": (
        ("macos_launch_agents", {}),
        ("macos_login_items", {}),
    ),
    "user_activity": (
        ("macos_bash_history", {}),
        ("macos_browser_history", {}),
    ),
    "system_inventory": (
        ("macos_users", {}),
    ),
    "filesystem": (
        ("macos_file_finder", {"SearchFilesGlob": "/Users/*/Downloads/**"}),
    ),
    "security": (
        ("macos_quarantine_events", {}),
        ("macos_tcc_database", {}),
    ),
}

MACOS_TOOLSETS = {
    role: tuple(tool_name for tool_name, _ in requests)
    for role, requests in MACOS_TOOL_REQUESTS.items()
}

ROLE_DESCRIPTIONS = {
    "process": "Process analysis",
    "network": "Network connection analysis",
    "persistence": "Persistence analysis",
    "execution": "Execution artifact analysis",
    "user_activity": "User activity analysis",
    "system_inventory": "System inventory analysis",
    "filesystem": "Filesystem and storage analysis",
    "security": "Security event and detection analysis",
}

ANALYSIS_ROLE_PROFILES = {
    "triage": ("process", "network"),
    "engagement": (
        "process",
        "network",
        "persistence",
        "execution",
        "user_activity",
        "system_inventory",
    ),
    "deep": (
        "process",
        "network",
        "persistence",
        "execution",
        "user_activity",
        "system_inventory",
        "filesystem",
        "security",
    ),
}

TOOL_DISPLAY_NAMES = {
    "linux_arp_cache": "Linux.Network.ArpCache",
    "linux_bash_history": "Linux.Sys.BashHistory",
    "linux_crontab": "Linux.Sys.Crontab",
    "linux_file_finder": "Linux.Search.FileFinder",
    "linux_groups": "Linux.Sys.Groups",
    "linux_journal_logs": "Linux.Forensics.Journal",
    "linux_last_user_login": "Linux.Sys.LastUserLogin",
    "linux_mounts": "Linux.Mounts",
    "linux_pslist": "Linux.Sys.Pslist",
    "linux_netstat_enriched": "Linux.Network.NetstatEnriched",
    "linux_services": "Linux.Sys.Services",
    "linux_ssh_authorized_keys": "Linux.Sys.SSHAuthorizedKeys",
    "linux_ssh_logins": "Linux.Syslog.SSHLogin",
    "linux_users": "Linux.Sys.Users",
    "macos_bash_history": "MacOS.Sys.BashHistory",
    "macos_browser_history": "MacOS.Applications.Chrome.History",
    "macos_file_finder": "MacOS.Search.FileFinder",
    "macos_launch_agents": "MacOS.Sys.LaunchAgents",
    "macos_login_items": "MacOS.Sys.LoginItems",
    "macos_netstat": "MacOS.Network.Netstat",
    "macos_pslist": "MacOS.Sys.Pslist",
    "macos_quarantine_events": "MacOS.Forensics.Quarantine",
    "macos_tcc_database": "MacOS.System.TCC",
    "macos_users": "MacOS.Sys.Users",
    "windows_pslist": "Windows.System.Pslist",
    "windows_netstat_enriched": "Windows.Network.NetstatEnriched/Netstat",
    "windows_scheduled_tasks": "Windows.System.TaskScheduler/Analysis",
    "windows_services": "Windows.System.Services",
    "windows_autoruns": "Windows.Sys.StartupItems",
    "windows_browser_history": "Windows.Applications.Chrome.History",
    "windows_dns_cache": "Windows.System.DNSCache",
    "windows_event_log_cleared": "Windows.EventLogs.Cleared",
    "windows_event_logs": "Windows.EventLogs.EvtxHunter",
    "windows_execution_amcache": "Windows.Detection.Amcache",
    "windows_execution_activitiesCache": "Windows.Forensics.Timeline",
    "windows_execution_bam": "Windows.Forensics.Bam",
    "windows_execution_prefetch": "Windows.Forensics.Prefetch",
    "windows_execution_shimcache": "Windows.Registry.AppCompatCache",
    "windows_execution_userassist": "Windows.Registry.UserAssist",
    "windows_evidence_of_download": "Windows.Analysis.EvidenceOfDownload",
    "windows_logon_events": "Windows.EventLogs.LogonSessions",
    "windows_malfind": "Windows.Detection.Malfind",
    "windows_mounted_mass_storage_usb": "Windows.Mounted.Mass.Storage",
    "windows_mountpoints2": "Windows.Registry.MountPoints2",
    "windows_mutants": "Windows.Detection.Mutants",
    "windows_ntfs_mft": "Windows.NTFS.MFT",
    "windows_ntfs_mft_search": "Windows.NTFS.MFT/Search",
    "windows_powershell_history": "Windows.System.Powershell.PSReadline",
    "windows_powershell_scriptblock": "Windows.EventLogs.PowerShellScriptBlock",
    "windows_rdp_sessions": "Windows.EventLogs.RDPAuth",
    "windows_recentdocs": "Windows.Registry.RecentDocs",
    "windows_recycle_bin": "Windows.Forensics.RecycleBin",
    "windows_shadow_copies": "Windows.System.ShadowCopies",
    "windows_shellbags": "Windows.Forensics.Shellbags",
    "windows_srum": "Windows.Forensics.SRUM",
    "windows_timestomp": "Windows.NTFS.Timestomp",
    "windows_usn_journal": "Windows.Forensics.Usn",
    "windows_wmi_persistence": "Windows.Persistence.PermanentWMIEvents",
}

SUSPICIOUS_KEYWORDS = (
    "grunt",
    "psexec",
    "mimikatz",
    "tor",
    "dragonforce",
    "fakenet",
    "autoruns",
    "ghidra",
    "malcat",
)

USER_WRITABLE_SEGMENTS = (
    "\\users\\",
    "\\programdata\\",
    "\\appdata\\",
    "\\temp\\",
    "/tmp/",
    "/var/tmp/",
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _duration_seconds(started_at: datetime, completed_at: datetime) -> float:
    return round((completed_at - started_at).total_seconds(), 3)


def _contains_keyword(value: str) -> bool:
    lowered = value.lower()
    return any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS)


def _looks_user_writable_path(value: str) -> bool:
    lowered = value.lower()
    return any(segment in lowered for segment in USER_WRITABLE_SEGMENTS)


def _is_external_address(value: Any) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _simplify_value(value: Any) -> Any:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, dict):
        simplified = {
            key: _simplify_value(nested_value)
            for key, nested_value in value.items()
        }
        return {key: nested for key, nested in simplified.items() if nested is not None}
    if isinstance(value, list):
        simplified_list = [_simplify_value(item) for item in value[:5]]
        return [item for item in simplified_list if item is not None]
    return value


def _compact_row(row: Any) -> Any:
    if not isinstance(row, dict):
        return row
    simplified = {
        key: _simplify_value(value)
        for key, value in row.items()
    }
    return {key: value for key, value in simplified.items() if value is not None}


@dataclass(frozen=True)
class CaseContext:
    hostname: str
    client_id: str
    org_id: Optional[str]
    os_type: str
    target: str
    platform_guidance: str
    shared_guidance: str

    @property
    def normalized_os_type(self) -> str:
        lowered = (self.os_type or "unknown").strip().lower()
        if lowered.startswith("win"):
            return "windows"
        if lowered.startswith("lin"):
            return "linux"
        if lowered.startswith("mac") or lowered in {"darwin", "osx"}:
            return "macos"
        return lowered


@dataclass(frozen=True)
class AnalystSpec:
    role: str
    description: str
    allowed_tools: tuple[str, ...]
    os_type: str


@dataclass
class AnalystResult:
    role: str
    status: str
    summary: str
    raw_response: str
    evidence: Dict[str, Any]
    allowed_tools: list[str]
    started_at: str
    completed_at: str
    duration_seconds: float
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "status": self.status,
            "summary": self.summary,
            "raw_response": self.raw_response,
            "evidence": self.evidence,
            "allowed_tools": self.allowed_tools,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


@dataclass
class EngagementResult:
    workflow: str
    hostname: str
    client_id: Optional[str]
    org_id: Optional[str]
    os_type: Optional[str]
    started_at: str
    completed_at: str = ""
    duration_seconds: float = 0.0
    manager_summary: str = ""
    analysts: Dict[str, AnalystResult] = field(default_factory=dict)
    errors: List[Dict[str, str]] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)

    def finalize(self, completed_at: datetime):
        self.completed_at = _isoformat(completed_at)
        started_dt = datetime.fromisoformat(self.started_at.replace("Z", "+00:00"))
        self.duration_seconds = _duration_seconds(started_dt, completed_at)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow": self.workflow,
            "hostname": self.hostname,
            "client_id": self.client_id,
            "org_id": self.org_id,
            "os_type": self.os_type,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "manager_summary": self.manager_summary,
            "analysts": {
                role: result.to_dict()
                for role, result in self.analysts.items()
            },
            "errors": self.errors,
            "skipped": self.skipped,
        }


class VelociraptorAgent:
    """
    Multi-stage agent for per-host forensic analysis workflows.
    """

    def __init__(
        self,
        model: Optional[str] = None,
        output_dir: Optional[str] = None,
        client_factory: Optional[Callable[..., VelociraptorMCPClient]] = None,
        max_parallel_analysts: int = 4,
        verbose: bool = False,
    ):
        self.model_provider = _model_provider()
        self.model = model or _default_model(self.model_provider)
        self.client_factory = client_factory or VelociraptorMCPClient
        self.verbose = verbose
        self.client = self._create_client(label="management agent")
        self.output_dir = output_dir or str(Path(__file__).resolve().parent / "output")
        self.max_parallel_analysts = max_parallel_analysts
        self.case_context_hint = os.environ.get("VELOCIRAPTOR_CASE_CONTEXT", "").strip()

    def _create_client(
        self,
        allowed_tools: Optional[List[str]] = None,
        label: Optional[str] = None,
    ) -> VelociraptorMCPClient:
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "verbose": self.verbose,
            "label": label,
        }
        if allowed_tools is not None:
            kwargs["default_allowed_tools"] = allowed_tools

        try:
            return self.client_factory(**kwargs)
        except TypeError:
            client = self.client_factory(self.model)
            if allowed_tools is not None and hasattr(client, "default_allowed_tools"):
                client.default_allowed_tools = set(allowed_tools)
            if hasattr(client, "verbose"):
                client.verbose = self.verbose
            if label is not None and hasattr(client, "label"):
                client.label = label
            return client

    async def initialize(self):
        """Initialize the agent and connect to MCP bridge."""
        await self.client.connect()
        print(f"✓ Agent initialized with {len(self.client.tools)} tools", flush=True)

    async def shutdown(self):
        """Cleanup and disconnect."""
        await self.client.disconnect()

    async def analyze_endpoint(
        self,
        hostname: str,
        analysis_type: str = "triage",
    ) -> Dict[str, Any]:
        """
        Perform automated analysis on an endpoint.

        Args:
            hostname: Target hostname or client_id.
            analysis_type: One of triage, process, network, persistence,
                execution, user_activity, system_inventory, filesystem,
                security, engagement, deep, or full.

        Returns:
            Structured analysis results.
        """
        print(f"\n🔍 Starting {analysis_type} analysis for: {hostname}", flush=True)
        self.client.reset_conversation()

        normalized_type = "engagement" if analysis_type == "full" else analysis_type
        if normalized_type in ANALYSIS_ROLE_PROFILES:
            results = await self._profile_workflow(hostname, normalized_type)
        elif normalized_type in ROLE_DESCRIPTIONS:
            results = await self._single_role_workflow(hostname, normalized_type)
        else:
            results = await self._profile_workflow(hostname, "triage")

        self._save_results(hostname, analysis_type, results)
        return results

    async def _resolve_client_info(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Resolve hostname to client metadata deterministically via the MCP tool."""
        payload = await self.client.call_tool_payload("client_info", {"hostname": hostname})
        if payload.get("ok") and payload.get("data"):
            return payload.get("data")

        payload = await self.client.call_tool_payload(
            "client_info",
            {"hostname": hostname, "search_all_orgs": True},
        )
        if payload.get("ok") and payload.get("data"):
            return payload.get("data")
        return None

    @staticmethod
    def _target_phrase(client_info: Dict[str, Any]) -> str:
        os_type = (client_info.get("OSType") or "unknown").lower()
        client_id = client_info["client_id"]
        org_id = client_info.get("OrgId")
        prefix = f"{os_type} " if os_type != "unknown" else ""
        if org_id:
            return f"{prefix}client {client_id} in org {org_id}"
        return f"{prefix}client {client_id}"

    @staticmethod
    def _platform_guidance(client_info: Dict[str, Any]) -> str:
        os_type = CaseContext(
            hostname="",
            client_id="",
            org_id=None,
            os_type=client_info.get("OSType") or "",
            target="",
            platform_guidance="",
            shared_guidance="",
        ).normalized_os_type
        if os_type == "windows":
            return "This endpoint is Windows. Use only approved Windows Velociraptor tools for your role."
        if os_type == "linux":
            return "This endpoint is Linux. Use only approved Linux Velociraptor tools for your role."
        if os_type == "macos":
            return "This endpoint is macOS. Use only approved macOS Velociraptor tools for your role."
        return "Choose tools based on the resolved endpoint metadata."

    def _shared_guidance(self) -> str:
        if self.case_context_hint:
            return f"{DEFAULT_SHARED_GUIDANCE} Case context: {self.case_context_hint}"
        return DEFAULT_SHARED_GUIDANCE

    async def _build_case_context(self, hostname: str) -> Optional[CaseContext]:
        client_info = await self._resolve_client_info(hostname)
        if not client_info:
            return None

        return CaseContext(
            hostname=hostname,
            client_id=client_info["client_id"],
            org_id=client_info.get("OrgId"),
            os_type=client_info.get("OSType") or "unknown",
            target=self._target_phrase(client_info),
            platform_guidance=self._platform_guidance(client_info),
            shared_guidance=self._shared_guidance(),
        )

    @staticmethod
    def _new_result(workflow: str, hostname: str) -> EngagementResult:
        return EngagementResult(
            workflow=workflow,
            hostname=hostname,
            client_id=None,
            org_id=None,
            os_type=None,
            started_at=_isoformat(_utc_now()),
        )

    @staticmethod
    def _tool_requests(spec: AnalystSpec) -> tuple[tuple[str, Dict[str, Any]], ...]:
        requests_by_os = {
            "windows": WINDOWS_TOOL_REQUESTS,
            "linux": LINUX_TOOL_REQUESTS,
            "macos": MACOS_TOOL_REQUESTS,
        }.get(spec.os_type, {})
        return requests_by_os.get(spec.role, ())

    @staticmethod
    def _tool_arguments(
        case_context: CaseContext,
        overrides: Dict[str, Any],
    ) -> Dict[str, Any]:
        arguments: Dict[str, Any] = {"client_id": case_context.client_id}
        if case_context.org_id:
            arguments["org_id"] = case_context.org_id
        arguments.update(overrides)
        return arguments

    @staticmethod
    def _collect_rows_from_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        data = payload.get("data")
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            return [data]
        return []

    @staticmethod
    def _tool_display_name(tool_name: str) -> str:
        return TOOL_DISPLAY_NAMES.get(tool_name, tool_name)

    def _emit_verbose_progress(self, label: str, message: str):
        if self.verbose:
            print(f"{label} {message}", file=sys.stderr)

    def _highlight_row(self, role: str, tool_name: str, row: Dict[str, Any]) -> bool:
        path = str(
            row.get("Exe")
            or row.get("Path")
            or row.get("AbsoluteExePath")
            or row.get("Command")
            or row.get("DownloadedFilePath")
            or row.get("Binary")
            or row.get("Name")
            or ""
        )
        command_line = str(row.get("CommandLine") or row.get("Arguments") or "")
        trusted = str(
            row.get("Authenticode.Trusted")
            or row.get("Trusted")
            or (row.get("Authenticode") or {}).get("Trusted")
            or (row.get("CertinfoServiceExe") or {}).get("Trusted")
            or ""
        ).lower()
        username = str(row.get("Username") or row.get("UserId") or row.get("UserAccount") or "")

        if role == "process":
            return (
                trusted in {"untrusted", "unsigned", "error"}
                or _looks_user_writable_path(path)
                or _contains_keyword(path)
                or _contains_keyword(command_line)
            )
        if role == "network":
            status = str(row.get("Status") or "").upper()
            return (
                (status == "ESTABLISHED" and _is_external_address(row.get("Raddr")))
                or _looks_user_writable_path(path)
                or _contains_keyword(path)
                or _contains_keyword(command_line)
            )
        if role == "persistence":
            return (
                _looks_user_writable_path(path)
                or trusted in {"untrusted", "unsigned", "error"}
                or (_contains_keyword(path) or _contains_keyword(command_line))
                or (
                    username
                    and "s-1-5-18" not in username.lower()
                    and "system" not in username.lower()
                )
            )
        if role == "execution":
            return (
                bool(row.get("HostUrl"))
                or _looks_user_writable_path(path)
                or _contains_keyword(path)
                or _contains_keyword(command_line)
            )
        if role in {"user_activity", "system_inventory", "filesystem"}:
            return (
                _looks_user_writable_path(path)
                or _contains_keyword(path)
                or _contains_keyword(command_line)
            )
        if role == "security":
            status = str(row.get("Status") or row.get("Result") or "").lower()
            return (
                _looks_user_writable_path(path)
                or _contains_keyword(path)
                or _contains_keyword(command_line)
                or status in {"suspicious", "malicious", "detected"}
                or any(
                    str(row.get(field) or "").strip().lower() in {"true", "yes", "1"}
                    for field in ("Matched", "Match", "Hit", "Suspicious", "Malicious")
                )
            )
        return False

    def _summarize_tool_rows(
        self,
        role: str,
        tool_name: str,
        rows: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        highlights = [
            _compact_row(row)
            for row in rows
            if self._highlight_row(role, tool_name, row)
        ][:8]
        sample_rows = [_compact_row(row) for row in rows[:3]]
        return {
            "ok": True,
            "row_count": len(rows),
            "highlights": highlights,
            "sample_rows": sample_rows,
        }

    async def _collect_role_evidence(
        self,
        client: VelociraptorMCPClient,
        spec: AnalystSpec,
        case_context: CaseContext,
    ) -> Dict[str, Any]:
        evidence = {
            "role": spec.role,
            "os_type": case_context.os_type,
            "target": case_context.target,
            "tool_results": {},
            "tool_errors": [],
        }

        for tool_name, overrides in self._tool_requests(spec):
            tool_display = self._tool_display_name(tool_name)
            self._emit_verbose_progress(client.label, f"running {tool_display}")
            payload = await client.call_tool_payload(
                tool_name,
                self._tool_arguments(case_context, overrides),
            )
            if payload.get("ok"):
                rows = self._collect_rows_from_payload(payload)
                self._emit_verbose_progress(
                    client.label,
                    f"collected {len(rows)} rows from {tool_display}",
                )
                evidence["tool_results"][tool_name] = self._summarize_tool_rows(
                    spec.role,
                    tool_name,
                    rows,
                )
            else:
                message = payload.get("error", "Unknown tool error")
                self._emit_verbose_progress(
                    client.label,
                    f"failed {tool_display}: {message}",
                )
                evidence["tool_results"][tool_name] = {
                    "ok": False,
                    "error": message,
                    "row_count": 0,
                    "highlights": [],
                    "sample_rows": [],
                }
                evidence["tool_errors"].append({
                    "tool": tool_name,
                    "message": message,
                })

        return evidence

    def _build_analyst_synthesis_prompt(
        self,
        spec: AnalystSpec,
        case_context: CaseContext,
        evidence: Dict[str, Any],
    ) -> str:
        focus = {
            "process": (
                "Identify suspicious processes, notable benign explanations, and "
                "the highest-priority follow-up process leads."
            ),
            "network": (
                "Identify suspicious connections, notable benign explanations, and "
                "the highest-priority follow-up network leads."
            ),
            "persistence": (
                "Identify suspicious persistence entries, notable benign explanations, "
                "and the highest-priority follow-up persistence leads."
            ),
            "execution": (
                "Identify suspicious execution evidence, notable benign explanations, "
                "and the highest-priority follow-up execution leads."
            ),
            "user_activity": (
                "Identify suspicious user activity, notable benign explanations, "
                "and the highest-priority follow-up user-activity leads."
            ),
            "system_inventory": (
                "Identify notable system inventory findings, unusual users, groups, "
                "mounts, removable storage, or host state, and the highest-priority "
                "follow-up inventory leads."
            ),
            "filesystem": (
                "Identify suspicious filesystem or storage activity, notable benign "
                "explanations, and the highest-priority follow-up filesystem leads."
            ),
            "security": (
                "Identify suspicious security events or detections, notable benign "
                "explanations, and the highest-priority follow-up detection leads."
            ),
        }
        return (
            f"You are the {spec.description.lower()} specialist for {case_context.target}. "
            f"{case_context.platform_guidance} {case_context.shared_guidance} "
            "Use only the evidence bundle below. Do not ask for more input. "
            "Provide a concise assessment with: 1) key findings, 2) benign vs suspicious "
            "assessment, 3) follow-up actions. "
            f"{focus[spec.role]}\n\n"
            f"Evidence bundle:\n{json.dumps(evidence, indent=2)}"
        )

    @staticmethod
    def _fallback_role_summary(spec: AnalystSpec, evidence: Dict[str, Any]) -> str:
        lines = [f"{spec.description} fallback summary"]
        for tool_name, result in evidence.get("tool_results", {}).items():
            if result.get("ok"):
                lines.append(
                    f"- {tool_name}: {result.get('row_count', 0)} rows, "
                    f"{len(result.get('highlights', []))} highlighted rows"
                )
            else:
                lines.append(f"- {tool_name}: error: {result.get('error', 'unknown error')}")
        if evidence.get("tool_errors"):
            lines.append("Some tool calls failed; review tool_errors in the evidence bundle.")
        return "\n".join(lines)

    def _select_analysts(
        self,
        case_context: CaseContext,
        requested_roles: Optional[List[str]] = None,
    ) -> tuple[List[AnalystSpec], List[Dict[str, str]]]:
        toolsets_by_os = {
            "windows": WINDOWS_TOOLSETS,
            "linux": LINUX_TOOLSETS,
            "macos": MACOS_TOOLSETS,
        }
        toolsets = toolsets_by_os.get(case_context.normalized_os_type, {})
        requested = requested_roles or list(toolsets.keys())

        specs: List[AnalystSpec] = []
        skipped: List[Dict[str, str]] = []
        for role in requested:
            allowed_tools = toolsets.get(role)
            if not allowed_tools:
                skipped.append({
                    "role": role,
                    "status": "not_applicable",
                    "reason": (
                        f"No {role} analyst is defined for {case_context.normalized_os_type} endpoints."
                    ),
                })
                continue

            specs.append(AnalystSpec(
                role=role,
                description=ROLE_DESCRIPTIONS[role],
                allowed_tools=allowed_tools,
                os_type=case_context.normalized_os_type,
            ))

        return specs, skipped

    async def _run_analyst(self, spec: AnalystSpec, case_context: CaseContext) -> AnalystResult:
        started_at = _utc_now()
        client = self._create_client(
            list(spec.allowed_tools),
            label=f"{spec.role} analyst",
        )
        evidence: Dict[str, Any] = {}
        try:
            await client.connect()
            client.reset_conversation()
            evidence = await self._collect_role_evidence(client, spec, case_context)
            successful_tools = [
                name
                for name, result in evidence["tool_results"].items()
                if result.get("ok")
            ]
            if not successful_tools:
                raise RuntimeError(
                    "; ".join(
                        item["message"] for item in evidence["tool_errors"]
                    ) or "No evidence could be collected."
                )

            self._emit_verbose_progress(
                client.label,
                f"summarizing evidence from {len(successful_tools)} collections",
            )
            synthesis_prompt = self._build_analyst_synthesis_prompt(
                spec,
                case_context,
                evidence,
            )
            response = await client.chat(
                synthesis_prompt,
                allowed_tools=[],
                system_prompt=ANALYST_SYSTEM_PROMPT,
            )
            if not response.strip():
                response = self._fallback_role_summary(spec, evidence)
            self._emit_verbose_progress(client.label, "summary complete")
            completed_at = _utc_now()
            return AnalystResult(
                role=spec.role,
                status="completed",
                summary=response,
                raw_response=response,
                evidence=evidence,
                allowed_tools=list(spec.allowed_tools),
                started_at=_isoformat(started_at),
                completed_at=_isoformat(completed_at),
                duration_seconds=_duration_seconds(started_at, completed_at),
            )
        except Exception as exc:
            completed_at = _utc_now()
            fallback_summary = (
                self._fallback_role_summary(spec, evidence)
                if evidence.get("tool_results")
                else ""
            )
            return AnalystResult(
                role=spec.role,
                status="error",
                summary=fallback_summary,
                raw_response=fallback_summary,
                evidence=evidence,
                allowed_tools=list(spec.allowed_tools),
                started_at=_isoformat(started_at),
                completed_at=_isoformat(completed_at),
                duration_seconds=_duration_seconds(started_at, completed_at),
                error=str(exc),
            )
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass

    async def _run_analysts(
        self,
        specs: List[AnalystSpec],
        case_context: CaseContext,
    ) -> Dict[str, AnalystResult]:
        semaphore = asyncio.Semaphore(self.max_parallel_analysts)

        async def run_with_limit(spec: AnalystSpec) -> AnalystResult:
            async with semaphore:
                return await self._run_analyst(spec, case_context)

        results = await asyncio.gather(*(run_with_limit(spec) for spec in specs))
        return {result.role: result for result in results}

    async def _synthesize_manager_summary(
        self,
        workflow: str,
        case_context: CaseContext,
        analyst_results: Dict[str, AnalystResult],
        skipped: List[Dict[str, str]],
        errors: List[Dict[str, str]],
    ) -> str:
        completed_results = {
            role: result.summary
            for role, result in analyst_results.items()
            if result.status == "completed"
        }
        if not completed_results:
            return "No completed analyst findings were produced."

        self.client.reset_conversation()
        prompt = (
            f"Synthesize the {workflow} investigation for {case_context.target}. "
            f"{case_context.shared_guidance} "
            "Summarize the key findings, likely benign explanations versus "
            "suspicious behavior, and the highest-priority follow-up items.\n\n"
            f"Analyst findings:\n{json.dumps(completed_results, indent=2)}\n\n"
            f"Skipped analysts:\n{json.dumps(skipped, indent=2)}\n\n"
            f"Errors:\n{json.dumps(errors, indent=2)}"
        )
        return await self.client.chat(
            prompt,
            allowed_tools=[],
            system_prompt=MANAGER_SYSTEM_PROMPT,
        )

    async def _run_structured_workflow(
        self,
        hostname: str,
        workflow: str,
        requested_roles: Optional[List[str]] = None,
        synthesize: bool = True,
    ) -> Dict[str, Any]:
        result = self._new_result(workflow, hostname)
        case_context = await self._build_case_context(hostname)
        if not case_context:
            result.errors.append({
                "role": "manager",
                "message": "Could not determine client_id",
            })
            result.manager_summary = "Could not determine endpoint metadata."
            completed_at = _utc_now()
            result.finalize(completed_at)
            return result.to_dict()

        result.client_id = case_context.client_id
        result.org_id = case_context.org_id
        result.os_type = case_context.os_type

        specs, skipped = self._select_analysts(case_context, requested_roles)
        result.skipped.extend(skipped)

        analyst_results = await self._run_analysts(specs, case_context) if specs else {}
        result.analysts.update(analyst_results)

        for analyst in analyst_results.values():
            if analyst.status == "error":
                result.errors.append({
                    "role": analyst.role,
                    "message": analyst.error or "Analyst execution failed.",
                })

        if synthesize:
            try:
                result.manager_summary = await self._synthesize_manager_summary(
                    workflow,
                    case_context,
                    analyst_results,
                    result.skipped,
                    result.errors,
                )
            except Exception as exc:
                result.errors.append({
                    "role": "manager",
                    "message": str(exc),
                })
                result.manager_summary = "Failed to generate manager summary."
        else:
            completed = next(
                (value.summary for value in analyst_results.values() if value.status == "completed"),
                "",
            )
            result.manager_summary = completed or "No completed analyst findings were produced."

        completed_at = _utc_now()
        result.finalize(completed_at)
        return result.to_dict()

    async def _profile_workflow(self, hostname: str, workflow: str) -> Dict[str, Any]:
        """Run a named analysis profile with its bounded analyst roles."""
        return await self._run_structured_workflow(
            hostname,
            workflow=workflow,
            requested_roles=list(ANALYSIS_ROLE_PROFILES[workflow]),
            synthesize=True,
        )

    async def _single_role_workflow(self, hostname: str, role: str) -> Dict[str, Any]:
        """Single-analyst workflow."""
        return await self._run_structured_workflow(
            hostname,
            workflow=role,
            requested_roles=[role],
            synthesize=False,
        )

    async def _engagement_workflow(self, hostname: str) -> Dict[str, Any]:
        """Multi-analyst engagement workflow."""
        return await self._profile_workflow(hostname, "engagement")

    async def batch_analyze(
        self,
        hostnames: List[str],
        analysis_type: str = "triage",
    ) -> List[Dict[str, Any]]:
        """Analyze multiple endpoints."""
        results = []

        for hostname in hostnames:
            try:
                result = await self.analyze_endpoint(hostname, analysis_type)
                results.append(result)
            except Exception as exc:
                results.append({
                    "hostname": hostname,
                    "workflow": "error",
                    "errors": [{"role": "manager", "message": str(exc)}],
                })

        return results

    def _save_results(self, hostname: str, analysis_type: str, results: Dict[str, Any]):
        """Save analysis results to JSON file."""
        os.makedirs(self.output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/{hostname}_{analysis_type}_{timestamp}.json"

        with open(filename, "w") as file_handle:
            json.dump(results, file_handle, indent=2)

        print(f"✓ Results saved to: {filename}", flush=True)


def _format_value(value: Any) -> str:
    if value is None:
        return "None"
    if isinstance(value, str):
        return value.strip() or "(empty)"
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2)
    return str(value)


def format_results_text(results: Dict[str, Any]) -> str:
    """Render analysis results in a readable text format."""
    lines = [f"Workflow: {results.get('workflow', 'unknown')}"]

    if results.get("hostname"):
        lines.append(f"Hostname: {results['hostname']}")
    if results.get("client_id"):
        lines.append(f"Client ID: {results['client_id']}")
    if results.get("org_id"):
        lines.append(f"Org ID: {results['org_id']}")
    if results.get("os_type"):
        lines.append(f"OS Type: {results['os_type']}")
    if results.get("duration_seconds") is not None:
        lines.append(f"Duration: {results.get('duration_seconds', 0)}s")

    manager_summary = results.get("manager_summary")
    if manager_summary:
        lines.append("")
        lines.append("Manager Summary:")
        lines.append(_format_value(manager_summary))

    analysts = results.get("analysts", {})
    if analysts:
        lines.append("")
        lines.append("Analysts:")
        for role, analyst in analysts.items():
            lines.append(
                f"[{role}] status={analyst.get('status', 'unknown')} "
                f"duration={analyst.get('duration_seconds', 0)}s"
            )
            if analyst.get("error"):
                lines.append(f"Error: {analyst['error']}")
            else:
                lines.append(_format_value(analyst.get("summary")))
            lines.append("")

    skipped = results.get("skipped", [])
    if skipped:
        lines.append("Skipped:")
        for item in skipped:
            lines.append(f"{item.get('role', 'unknown')}: {item.get('reason', 'skipped')}")
        lines.append("")

    errors = results.get("errors", [])
    if errors:
        lines.append("Errors:")
        for error in errors:
            lines.append(f"{error.get('role', 'unknown')}: {error.get('message', 'error')}")

    return "\n".join(lines).rstrip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Velociraptor agent analysis for a target hostname"
    )
    parser.add_argument(
        "hostname",
        nargs="?",
        default="RE-DEV",
        help="Target hostname to analyze (default: RE-DEV)",
    )
    parser.add_argument(
        "-t",
        "--analysis-type",
        default="triage",
        choices=[
            "triage",
            "process",
            "network",
            "persistence",
            "execution",
            "user_activity",
            "system_inventory",
            "filesystem",
            "security",
            "engagement",
            "deep",
            "full",
        ],
        help="Analysis workflow to run",
    )
    parser.add_argument(
        "--output-type",
        default="json",
        choices=["json", "text"],
        help="Print machine-readable JSON or a readable text summary",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose MCP client connection and tool-call diagnostics",
    )
    return parser.parse_args()


async def main():
    """CLI entry point for the agent."""
    args = parse_args()
    agent = VelociraptorAgent(verbose=args.verbose)

    try:
        await agent.initialize()

        results = await agent.analyze_endpoint(
            hostname=args.hostname,
            analysis_type=args.analysis_type,
        )

        print("\n" + "=" * 60)
        print("ANALYSIS COMPLETE")
        print("=" * 60)
        if args.output_type == "text":
            print(format_results_text(results))
        else:
            print(json.dumps(results, indent=2))
    finally:
        await agent.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
