from mcp.server.fastmcp import FastMCP

import os
import asyncio
import ast
import json
import logging
import re
from velociraptor_api import *


# Keep stdio responses clean by suppressing chatty MCP library info logs.
logging.getLogger("mcp").setLevel(logging.WARNING)

mcp = FastMCP("velociraptor-mcp")

# velociraptor_api loads repo-local .env before resolving VELOCIRAPTOR_API_CONFIG,
# ./api_client.yaml, or ~/.config/api_client.yaml.
init_stub(os.environ.get("VELOCIRAPTOR_API_CONFIG"))
api_list_orgs = list_orgs

ArtifactParameters = dict[str, ParameterValue]
ENABLE_DANGEROUS_TOOLS = os.environ.get("ENABLE_DANGEROUS_TOOLS", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
DANGEROUS_TOOLS_WARNING = (
    "This tool is disabled by default. Set ENABLE_DANGEROUS_TOOLS=true "
    "only when you accept the endpoint impact risk."
)


def _json_success(data) -> str:
    return json.dumps({"ok": True, "data": data}, default=str)


def _json_error(message: str) -> str:
    return json.dumps({"ok": False, "error": message})


def _run_json_tool(func, *args, **kwargs) -> str:
    try:
        return _json_success(func(*args, **kwargs))
    except Exception as exc:
        return _json_error(str(exc))


def _run_collection_tool(
    client_id: str,
    artifact: str,
    parameters: ArtifactParameters | None,
    fields: str,
    result_scope: str,
    org_id: str = "",
) -> str:
    return _run_json_tool(
        realtime_collection,
        client_id,
        artifact,
        parameters,
        fields,
        result_scope,
        org_id,
    )


def _start_collection_tool(
    client_id: str,
    artifact: str,
    parameters: ArtifactParameters | None = None,
    timeout: int | None = None,
    org_id: str = "",
) -> str:
    try:
        response = start_collection(
            client_id,
            artifact,
            parameters,
            timeout=timeout,
            org_id=org_id,
        )
    except Exception as exc:
        return _json_error(str(exc))

    if not isinstance(response, list) or not response or "flow_id" not in response[0]:
        return _json_error(f"Failed to start collection: {response}")

    return _json_success(response[0])


def _split_legacy_parameters(parameters: str) -> list[str]:
    parts = []
    current = []
    quote = None
    escaped = False

    for char in parameters:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            current.append(char)
            quote = char
            continue
        if char == ",":
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)

    if quote:
        raise ValueError("Unterminated quoted value in parameters.")

    final_part = "".join(current).strip()
    if final_part:
        parts.append(final_part)
    return parts


def _parse_legacy_parameter_value(raw_value: str):
    value = raw_value.strip()
    if not value:
        raise ValueError("Parameter values must not be empty.")

    if value[0] in ("'", '"', "["):
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(f"Invalid legacy parameter value: {value!r}") from exc
        return normalize_parameter_value(parsed)

    lowered = value.lower()
    if lowered == "null" or lowered == "none":
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?(?:\d+\.\d*|\.\d+)", value):
        return float(value)

    raise ValueError(
        "Legacy parameters must use scalar values or list literals like "
        "Name='value', Count=1, Enabled=true, or Targets=['_BasicCollection']."
    )


def _parse_legacy_parameters(parameters: str) -> ArtifactParameters:
    parsed: ArtifactParameters = {}
    for assignment in _split_legacy_parameters(parameters):
        name, separator, raw_value = assignment.partition("=")
        if not separator:
            raise ValueError(
                "Legacy parameters must be comma-separated key=value pairs."
            )
        key = name.strip()
        if not VALID_PARAMETER_NAME_RE.fullmatch(key):
            raise ValueError(f"Invalid parameter name: {key!r}")
        parsed[key] = _parse_legacy_parameter_value(raw_value)

    return parsed


def _parse_collection_parameters(parameters: str) -> ArtifactParameters | None:
    cleaned = parameters.strip()
    if not cleaned:
        return None
    if not cleaned.startswith("{"):
        return _parse_legacy_parameters(cleaned)

    decoded = json.loads(cleaned)
    if not isinstance(decoded, dict):
        raise ValueError("parameters JSON must be an object.")
    return {
        key: normalize_parameter_value(value)
        for key, value in decoded.items()
    }


def _summarize_artifacts(name_regex: str, org_id: str = "") -> list[dict]:
    vql = f"""
    LET params(data) = SELECT name FROM data
    SELECT name, description, params(data=parameters) AS parameters
    FROM artifact_definitions()
    WHERE type =~ 'client' AND name =~ '{name_regex}'
    """

    def shorten(desc: str) -> str:
        return desc.strip().split(".")[0][:120].rstrip() + "..." if desc else ""

    results = run_vql_query(vql, org_id=org_id)
    return [
        {
            "name": row["name"],
            "short_description": shorten(row.get("description", "")),
            "parameters": [param["name"] for param in row.get("parameters", [])],
        }
        for row in results
    ]


def _run_dangerous_collection(
    client_id: str,
    artifact: str,
    parameters: ArtifactParameters | None = None,
    org_id: str = "",
) -> str:
    if not ENABLE_DANGEROUS_TOOLS:
        return _json_error(DANGEROUS_TOOLS_WARNING)
    return _start_collection_tool(client_id, artifact, parameters, org_id=org_id)

@mcp.tool()
def list_orgs() -> str:
    """
    List available Velociraptor orgs for multi-tenant deployments.

    Returns:
        A list of org metadata including OrgId and Name.
    """
    return _run_json_tool(api_list_orgs)


@mcp.tool()
def client_info(
    hostname: str,
    org_id: str = "",
    search_all_orgs: bool = False,
) -> str:
    """
    Retrieve client information from the Velociraptor server.

    Args:
        hostname: Hostname or FQDN of the target endpoint.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        search_all_orgs: Search across orgs when no org_id is supplied.

    Returns:
        A dictionary containing client metadata, including the client_id,
        which can be used to target other artifact collections. When
        search_all_orgs is true, the response may also include OrgId/OrgName.
    """
    try:
        result = find_client_info(
            hostname,
            org_id=org_id,
            search_all_orgs=search_all_orgs,
        )
    except Exception as exc:
        return _json_error(str(exc))

    if result is None:
        return _json_error(f"Client not found: {hostname}")

    return _json_success(result)


@mcp.tool()
def list_clients(
    search: str = ".",
    os_filter: str = ".",
    limit: int = 100,
    org_id: str = "",
) -> str:
    """
    List endpoints registered with Velociraptor.

    Args:
        search: Regex for hostname, FQDN, or client_id.
        os_filter: Regex for OS type such as windows, linux, or darwin.
        limit: Maximum rows to return.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
    """
    return _run_json_tool(list_all_clients, search, os_filter, limit, org_id)


@mcp.tool()
async def hunt_across_fleet(
    artifact: str,
    org_id: str = "",
    parameters: ArtifactParameters | None = None,
    legacy_parameters: str = "",
    description: str = "",
    os_filter: str = "",
) -> str:
    """
    Start a Velociraptor hunt across multiple endpoints and return hunt metadata.

    Args:
        artifact: Artifact to collect.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        parameters: Structured artifact parameters.
        legacy_parameters: Backward-compatible key=value parameter string.
        description: Human-readable hunt description.
        os_filter: Optional Velociraptor OS filter.
    """
    if parameters is not None and legacy_parameters.strip():
        return _json_error(
            "Provide either 'parameters' or 'legacy_parameters', not both."
        )
    try:
        parsed_parameters = parameters
        if legacy_parameters.strip():
            parsed_parameters = _parse_collection_parameters(legacy_parameters)
        elif parameters is not None:
            parsed_parameters = {
                key: normalize_parameter_value(value)
                for key, value in parameters.items()
            }
        result = start_hunt(
            artifact,
            parsed_parameters,
            description,
            os_filter,
            org_id,
        )
    except Exception as exc:
        return _json_error(str(exc))
    return _json_success(result[0] if result else {})


@mcp.tool()
async def get_hunt_results_tool(
    hunt_id: str,
    artifact: str,
    org_id: str = "",
    fields: str = "*",
    limit: int = 500,
) -> str:
    """
    Retrieve rows from a completed Velociraptor hunt.
    """
    return _run_json_tool(get_hunt_results, hunt_id, artifact, fields, limit, org_id)


@mcp.tool()
def run_vql(query: str, org_id: str = "") -> str:
    """
    Run arbitrary VQL. Disabled unless ENABLE_DANGEROUS_TOOLS=true.
    """
    if not ENABLE_DANGEROUS_TOOLS:
        return _json_error(DANGEROUS_TOOLS_WARNING)
    return _run_json_tool(run_vql_query, query, org_id)

@mcp.tool()
async def linux_pslist(
    client_id: str,
    org_id: str = "",
    ProcessRegex: str = ".",
    Fields: str = "*"
) -> str:
    """
    List running processes on a Linux host.

    Args:
        client_id: The Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        ProcessRegex: Case-insensitive regex to filter process names.
        Fields: Comma-separated string of fields to return.

    Returns:
        Process list as a string or error message.

    """
    artifact = "Linux.Sys.Pslist"
    result_scope = ""
    parameters = {"ProcessRegex": ProcessRegex}

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

@mcp.tool()
async def linux_groups(
    client_id: str,
    org_id: str = "",
    GroupFile: str = "/etc/group",
    Fields: str = "*"
) -> str:
    """
    List groups on a Linux host.
    
    Args:
        client_id: The Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        GroupFile: The location of the group file
        Fields: Comma-separated string of fields to return.

    Returns:
        The group names as a string or error message.

    """
    artifact = "Linux.Sys.Groups"
    result_scope = ""
    parameters = {"GroupFile": GroupFile}

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

@mcp.tool()
async def linux_mounts(
    client_id: str,
    org_id: str = "",
    Fields: str = "*"
) -> str:
    """
    List mounts on a Linux host.
    
    Args:
        client_id: The Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated string of fields to return.

    Returns:
        The mounted filesystems as a string or error message.

    """
    artifact = "Linux.Mounts"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

@mcp.tool()
async def linux_netstat_enriched(
    client_id: str,
    org_id: str = "",
    IPRegex: str = ".",
    PortRegex: str = ".",
    ProcessNameRegex: str = ".",
    UsernameRegex: str = ".",
    ConnectionStatusRegex: str= "LISTEN|ESTAB",
    ProcessPathRegex: str = ".",
    CommandLineRegex: str = ".",
    CallChainRegex: str = ".",
    Fields: str = "*"
) -> str:
    """
    List network connections (netstat) with process metadata on a Linux host.
    
    Args:
        client_id: The Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        IPRegex: Regex to filter remote/local IP addresses.
        PortRegex: Regex to filter local/remote ports (e.g., '^443$').
        ProcessNameRegex: Regex to filter process names.
        UsernameRegex: Regex to filter user accounts associated with the process.
        ConnectionStatusRegex: Regex to filter connection status.
        ProcessPathRegex: Regex to filter full process paths.
        CommandLineRegex: Regex to filter command-line arguments.
        CallChainRegex: Regex to filter process callchain.
        Fields: Comma-separated string of fields to return.

    Returns:
        Netstat results as a string or error message.

    """
    artifact = "Linux.Network.NetstatEnriched"
    result_scope = ""
    parameters = {
        "IPRegex": IPRegex,
        "PortRegex": PortRegex,
        "ProcessNameRegex": ProcessNameRegex,
        "UsernameRegex": UsernameRegex,
        "ConnectionStatusRegex": ConnectionStatusRegex,
        "ProcessPathRegex": ProcessPathRegex,
        "CommandLineRegex": CommandLineRegex,
        "CallChainRegex": CallChainRegex,
    }

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

@mcp.tool()
async def linux_users(
    client_id: str,
    org_id: str = "",
    Fields: str = "*"
) -> str:
    """
    List users on a Linux host.
    
    Args:
        client_id: The Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated string of fields to return.

    Returns:
        The user results as a string or error message.

    """
    artifact = "Linux.Sys.Users"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)


@mcp.tool()
async def linux_crontab(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Collect Linux crontab entries for persistence review.
    """
    return _run_collection_tool(client_id, "Linux.Sys.Crontab", None, Fields, "", org_id)


@mcp.tool()
async def linux_services(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Collect Linux systemd service definitions and state.
    """
    return _run_collection_tool(client_id, "Linux.Sys.Services", None, Fields, "", org_id)


@mcp.tool()
async def linux_ssh_authorized_keys(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Collect Linux authorized_keys files to identify SSH backdoors.
    """
    return _run_collection_tool(
        client_id,
        "Linux.Sys.SSHAuthorizedKeys",
        None,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def linux_bash_history(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Collect Linux shell history from user home directories.
    """
    return _run_collection_tool(client_id, "Linux.Sys.BashHistory", None, Fields, "", org_id)


@mcp.tool()
async def linux_ssh_logins(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Parse Linux SSH authentication events from syslog/auth logs.
    """
    return _run_collection_tool(client_id, "Linux.Syslog.SSHLogin", None, Fields, "", org_id)


@mcp.tool()
async def linux_last_user_login(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Parse Linux utmp/wtmp login history.
    """
    return _run_collection_tool(
        client_id,
        "Linux.Sys.LastUserLogin",
        None,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def linux_arp_cache(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Dump Linux ARP cache entries.
    """
    return _run_collection_tool(client_id, "Linux.Network.ArpCache", None, Fields, "", org_id)


@mcp.tool()
async def linux_journal_logs(
    client_id: str,
    org_id: str = "",
    SearchRegex: str = ".",
    DateAfter: str = "",
    DateBefore: str = "",
    Fields: str = "*",
) -> str:
    """
    Search Linux systemd journal logs.
    """
    parameters = {
        "SearchRegex": SearchRegex,
        "DateAfter": DateAfter,
        "DateBefore": DateBefore,
    }
    return _run_collection_tool(
        client_id,
        "Linux.Forensics.Journal",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def linux_file_finder(
    client_id: str,
    org_id: str = "",
    SearchFilesGlob: str = "/**",
    SearchGlob: str = "",
    Upload_File: bool = False,
    YaraRule: str = "",
    Hash: str = "",
    HashRegex: str = "",
    Calculate_Hash: bool = False,
    MoreRecentThan: str = "",
    ModifiedBefore: str = "",
    ExcludePathRegex: str = "",
    LocalFilesystemOnly: bool = False,
    OneFilesystem: bool = False,
    DoNotFollowSymlinks: bool = False,
    Fields: str = "*",
) -> str:
    """
    Search Linux files by glob or YARA rule using documented FileFinder params.
    """
    if Hash or HashRegex:
        Calculate_Hash = True
    if SearchGlob:
        SearchFilesGlob = SearchGlob
    parameters = {
        "SearchFilesGlob": SearchFilesGlob,
        "Upload_File": Upload_File,
        "YaraRule": YaraRule,
        "Calculate_Hash": Calculate_Hash,
        "MoreRecentThan": MoreRecentThan,
        "ModifiedBefore": ModifiedBefore,
        "ExcludePathRegex": ExcludePathRegex,
        "LocalFilesystemOnly": LocalFilesystemOnly,
        "OneFilesystem": OneFilesystem,
        "DoNotFollowSymlinks": DoNotFollowSymlinks,
    }
    return _run_collection_tool(
        client_id,
        "Linux.Search.FileFinder",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def macos_pslist(
    client_id: str,
    org_id: str = "",
    ProcessRegex: str = ".",
    Fields: str = "*",
) -> str:
    """
    List running processes on a macOS host.
    """
    return _run_collection_tool(
        client_id,
        "MacOS.Sys.Pslist",
        {"ProcessRegex": ProcessRegex},
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def macos_users(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    List local user accounts on a macOS host.
    """
    return _run_collection_tool(client_id, "MacOS.Sys.Users", None, Fields, "", org_id)


@mcp.tool()
async def macos_netstat(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    List network connections on a macOS host.
    """
    return _run_collection_tool(client_id, "MacOS.Network.Netstat", None, Fields, "", org_id)


@mcp.tool()
async def macos_launch_agents(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    List macOS LaunchAgents and LaunchDaemons.
    """
    return _run_collection_tool(
        client_id,
        "MacOS.Sys.LaunchAgents",
        None,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def macos_login_items(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    List macOS login items.
    """
    return _run_collection_tool(client_id, "MacOS.Sys.LoginItems", None, Fields, "", org_id)


@mcp.tool()
async def macos_bash_history(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Collect macOS bash and zsh history.
    """
    return _run_collection_tool(client_id, "MacOS.Sys.BashHistory", None, Fields, "", org_id)


@mcp.tool()
async def macos_browser_history(
    client_id: str,
    org_id: str = "",
    URLRegex: str = ".",
    historyGlobs: str = "",
    urlSQLQuery: str = "",
    userRegex: str = ".",
    Fields: str = "*",
) -> str:
    """
    Collect macOS browser history from supported browsers.
    """
    if URLRegex != ".":
        return _json_error(
            "MacOS.Applications.Chrome.History does not expose URLRegex; "
            "custom filtering requires urlSQLQuery."
        )
    parameters = {
        "historyGlobs": historyGlobs,
        "urlSQLQuery": urlSQLQuery,
        "userRegex": userRegex,
    }
    return _run_collection_tool(
        client_id,
        "MacOS.Applications.Chrome.History",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def macos_quarantine_events(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Parse macOS quarantine events for downloaded files.
    """
    return _run_collection_tool(
        client_id,
        "MacOS.Forensics.Quarantine",
        None,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def macos_tcc_database(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Parse the macOS TCC privacy permission database.
    """
    return _run_collection_tool(client_id, "MacOS.System.TCC", None, Fields, "", org_id)


@mcp.tool()
async def macos_file_finder(
    client_id: str,
    org_id: str = "",
    SearchFilesGlob: str = "/**",
    SearchGlob: str = "",
    Upload_File: bool = False,
    YaraRule: str = "",
    Hash: str = "",
    HashRegex: str = "",
    Fetch_Xattr: bool = False,
    Calculate_Hash: bool = False,
    MoreRecentThan: str = "",
    ModifiedBefore: str = "",
    DoNotFollowSymlinks: bool = False,
    Fields: str = "*",
) -> str:
    """
    Search macOS files by glob or YARA rule using documented FileFinder params.
    """
    if Hash or HashRegex:
        Calculate_Hash = True
    if SearchGlob:
        SearchFilesGlob = SearchGlob
    parameters = {
        "SearchFilesGlob": SearchFilesGlob,
        "Upload_File": Upload_File,
        "YaraRule": YaraRule,
        "Fetch_Xattr": Fetch_Xattr,
        "Calculate_Hash": Calculate_Hash,
        "MoreRecentThan": MoreRecentThan,
        "ModifiedBefore": ModifiedBefore,
        "DoNotFollowSymlinks": DoNotFollowSymlinks,
    }
    return _run_collection_tool(
        client_id,
        "MacOS.Search.FileFinder",
        parameters,
        Fields,
        "",
        org_id,
    )

@mcp.tool()
async def windows_pslist(
    client_id: str,
    org_id: str = "",
    ProcessRegex: str = ".",
    PidRegex: str = ".",
    ExePathRegex: str = ".",
    CommandLineRegex: str = ".",
    UsernameRegex: str = ".",
    Fields: str = "Pid, Ppid, TokenIsElevated, Name, Exe, CommandLine, Username, Authenticode.Trusted"
) -> str:
    """
    List running processes on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        ProcessRegex: Case-insensitive regex to filter process names.
        PidRegex: Regex to filter process IDs.
        ExePathRegex: Regex to filter executable path on disk.
        CommandLineRegex: Regex to filter process command line.
        UsernameRegex: Regex to filter user context of the process.
        Fields: Comma-separated list of fields to return.

    Returns:
        Process list results as a string or error message.
    """
    artifact = "Windows.System.Pslist"
    result_scope = ""
    parameters = {
        "ProcessRegex": ProcessRegex,
        "PidRegex": PidRegex,
        "ExePathRegex": ExePathRegex,
        "CommandLineRegex": CommandLineRegex,
        "UsernameRegex": UsernameRegex,
    }

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

@mcp.tool()
async def windows_netstat_enriched(
    client_id: str,
    org_id: str = "",
    IPRegex: str = ".",
    PortRegex: str = ".",
    ProcessNameRegex: str = ".",
    ProcessPathRegex: str = ".",
    CommandLineRegex: str = ".",
    UsernameRegex: str = ".",
    Fields: str = "Pid,Ppid,Name,Path,CommandLine,Username,Authenticode.Trusted,Type,Status,Laddr,Lport,Raddr,Rport"
) -> str:
    """
    List network connections (netstat) with process metadata on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        IPRegex: Regex to filter remote/local IP addresses.
        PortRegex: Regex to filter local/remote ports (e.g., '^443$').
        ProcessNameRegex: Regex to filter process names.
        ProcessPathRegex: Regex to filter full process paths.
        CommandLineRegex: Regex to filter command-line arguments.
        UsernameRegex: Regex to filter user accounts associated with the process.
        Fields: Comma-separated list of fields to return.

    Returns:
        Netstat results as a string or error message.
    """
    artifact = "Windows.Network.NetstatEnriched/Netstat"
    result_scope = ""
    parameters = {
        "IPRegex": IPRegex,
        "PortRegex": PortRegex,
        "ProcessNameRegex": ProcessNameRegex,
        "ProcessPathRegex": ProcessPathRegex,
        "CommandLineRegex": CommandLineRegex,
        "UsernameRegex": UsernameRegex,
    }

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

##
## Persistence 
@mcp.tool()
async def windows_scheduled_tasks(
    client_id: str,
    org_id: str = "",
    Fields: str = "OSPath,Mtime,Command,ExpandedCommand,Arguments,ComHandler,UserId,StartBoundary,Authenticode"
) -> str:
    """
    List scheduled tasks (persistance) with metadata on a Windows host

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        Scheduled task results as a string or error message.
    """
    artifact = "Windows.System.TaskScheduler"
    result_scope = "/Analysis"
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)


@mcp.tool()
async def windows_services(
    client_id: str,
    org_id: str = "",
    Fields: str = "UserAccount,Created,ServiceDll,FailureCommand,FailureActions,AbsoluteExePath,HashServiceExe,CertinfoServiceExe,HashServiceDll,CertinfoServiceDll"
) -> str:
    """
    List services with metadata on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        Service artifact results as a string or error message.
    """
    artifact = "Windows.System.Services"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)


##
## User Activity 

@mcp.tool()
async def windows_recentdocs(
    client_id: str,
    org_id: str = "",
    Fields: str = "Username,LastWriteTime,Value,Key,MruEntries,HiveName"
) -> str:
    """
    Collect RecentDocs from Registry on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        RecentDocs artifact results as a string or error message.
    """
    artifact = "Windows.Registry.RecentDocs"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)


@mcp.tool()
async def windows_shellbags(
    client_id: str,
    org_id: str = "",
    Fields: str = "ModTime,Name,_OSPath,Hive,KeyPath,Description,Path,_RawData,_Parsed"
) -> str:
    """
     Collect Shellbags from Registry on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        Shellbags artifact results as a string or error message.
    """
    artifact = "Windows.Forensics.Shellbags"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)


@mcp.tool()
async def windows_mounted_mass_storage_usb(
    client_id: str,
    org_id: str = "",
    Fields: str = "KeyLastWriteTimestamp, KeyName, FriendlyName, HardwareID"
) -> str:
    """
        Collect evidence of mounted mass storage from Registry on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        Mounted mass storage artifact results as a string or error message.
    """
    artifact = "Windows.Mounted.Mass.Storage"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

@mcp.tool()
async def windows_evidence_of_download(
    client_id: str,
    org_id: str = "",
    Fields: str = "DownloadedFilePath,_ZoneIdentifierContent,FileHash,HostUrl,ReferrerUrl"
) -> str:
    """
    Collect evidence of download from a Windows host.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        Evidence of Download artifact results as a string or error message.
    """
    artifact = "Windows.Analysis.EvidenceOfDownload"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

@mcp.tool()
async def windows_mountpoints2(
    client_id: str,
    org_id: str = "",
    Fields: str = "ModifiedTime, MountPoint, Hive, Key"
) -> str:
    """
    Collect evidence of download from a Windows host.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        Evidence of Download artifact results as a string or error message.
    """
    artifact = "Windows.Registry.MountPoints2"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)


@mcp.tool()
async def windows_event_log_cleared(
    client_id: str,
    org_id: str = "",
    DateAfter: str = "",
    DateBefore: str = "",
    Fields: str = "EventTime,Computer,Channel,EventID,EventData,Message",
) -> str:
    """
    Detect Windows event log clearing events.
    """
    parameters = {
        "ChannelRegex": "Security|System",
        "IdRegex": "104|1102",
        "DateAfter": DateAfter,
        "DateBefore": DateBefore,
    }
    return _run_collection_tool(
        client_id,
        "Windows.EventLogs.EvtxHunter",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_timestomp(
    client_id: str,
    org_id: str = "",
    DateAfter: str = "",
    DateBefore: str = "",
    Fields: str = "*",
) -> str:
    """
    Detect NTFS timestamp anomalies that may indicate timestomping.
    """
    parameters = {
        "DateAfter": DateAfter,
        "DateBefore": DateBefore,
    }
    return _run_collection_tool(
        client_id,
        "Windows.NTFS.Timestomp",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_shadow_copies(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Enumerate Windows Volume Shadow Copies.
    """
    parameters = {"WMIQuery": "SELECT * FROM Win32_ShadowCopy"}
    return _run_collection_tool(
        client_id,
        "Windows.System.WMIQuery",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_malfind(
    client_id: str,
    org_id: str = "",
    ProcessRegex: str = ".",
    PidRegex: str = ".",
    Fields: str = "*",
) -> str:
    """
    Detect suspicious unbacked Windows process memory regions.
    """
    parameters = {"ProcessRegex": ProcessRegex, "PidRegex": PidRegex}
    return _run_collection_tool(
        client_id,
        "Windows.Detection.Malfind",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_mutants(
    client_id: str,
    org_id: str = "",
    MutantRegex: str = ".",
    MutantNameRegex: str = "",
    ProcessRegex: str = ".",
    MutantWhitelistRegex: str = "",
    Fields: str = "*",
) -> str:
    """
    Enumerate Windows mutants/mutexes for malware hunting.
    """
    if not MutantNameRegex:
        MutantNameRegex = MutantRegex
    return _run_collection_tool(
        client_id,
        "Windows.Detection.Mutants",
        {
            "processRegex": ProcessRegex,
            "MutantNameRegex": MutantNameRegex,
            "MutantWhitelistRegex": MutantWhitelistRegex,
        },
        Fields,
        "",
        org_id,
    )


##
## Evidence of execution
@mcp.tool()
async def windows_execution_amcache(
    client_id: str,
    org_id: str = "",
    Fields: str = "FullPath,SHA1,ProgramID,FileDescription,FileVersion,Publisher,CompileTime,LastModified,LastRunTime"
) -> str:
    """
    Collect evidence of execution from Amcache on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        Amcache artifact results as a string or error message.
    """
    artifact = "Windows.Detection.Amcache"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)


@mcp.tool()
async def windows_execution_bam(
    client_id: str,
    org_id: str = "",
    Fields: str = "*"
) -> str:
    """
    Extract evidence of execution from the BAM (Background Activity Moderator) registry key on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        BAM artifact results as a string or error message.
    """
    artifact = "Windows.Forensics.Bam"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

@mcp.tool()
async def windows_execution_activitiesCache(
    client_id: str,
    org_id: str = "",
    Fields: str = "*"
) -> str:
    """
    Evidence of execution from activitiesCache.db (windows timeline) of system activity on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        Timeline artifact results as a string or error message.
    """
    artifact = "Windows.Forensics.Timeline"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

@mcp.tool()
async def windows_execution_userassist(
    client_id: str,
    org_id: str = "",
    Fields: str = "Name,User,LastExecution,NumberOfExecutions"
) -> str:
    """
    Extract evidence of execution from UserAssist registry keys.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        UserAssist artifact results as a string or error message.
    """
    artifact = "Windows.Registry.UserAssist"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

@mcp.tool()
async def windows_execution_shimcache(
    client_id: str,
    org_id: str = "",
    Fields: str = "Position,ModificationTime,Path,ExecutionFlag,ControlSet"
) -> str:
    """
    Parse ShimCache (AppCompatCache) entries from the registry on a Windows host.

    Note:
        Presence of a ShimCache entry may not indicate actual execution—only that the file was accessed or observed by the system.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        ShimCache (AppCompatCache) artifact results as a string or error message.
    """
    artifact = "Windows.Registry.AppCompatCache"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)


@mcp.tool()
async def windows_execution_prefetch(
    client_id: str,
    org_id: str = "",
    Fields: str = "Binary,CreationTime,LastRunTimes,RunCount,Hash" 
    #"Executable,LastRunTimes,RunCount,PrefetchFileName,Version,Hash,CreationTime,ModificationTime,Binary"
) -> str:
    """
    Parse Prefetch files on a Windows host to identify previously executed programs.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        Fields: Comma-separated list of fields to return.

    Returns:
        Prefetch artifact results as a string or error message.
    """
    artifact = "Windows.Forensics.Prefetch"
    result_scope = ""
    parameters = None  # No parameters for this artifact

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)


@mcp.tool()
async def windows_ntfs_mft_search(
    client_id: str,
    org_id: str = "",
    MFTDrive: str = "C:",
    PathRegex: str = ".",
    FileRegex: str = ".",
    DateAfter: str = "",
    DateBefore: str = "",
    Fields: str = "*",
) -> str:
    """
    Search the Windows MFT by filename regex.
    """
    parameters = {
        "MFTDrive": MFTDrive,
        "FileRegex": FileRegex,
        "PathRegex": PathRegex,
        "DateAfter": DateAfter,
        "DateBefore": DateBefore,
    }
    return _run_collection_tool(
        client_id,
        "Windows.NTFS.MFT",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_event_logs(
    client_id: str,
    org_id: str = "",
    EvtxGlob: str = "%SystemRoot%\\System32\\winevt\\Logs\\*.evtx",
    IocRegex: str = ".",
    SearchRegex: str = "",
    WhitelistRegex: str = "",
    PathRegex: str = ".",
    ChannelRegex: str = ".",
    ProviderRegex: str = ".",
    IdRegex: str = ".",
    EventIDRegex: str = "",
    VSSAnalysisAge: int = 0,
    SearchVSS: bool = False,
    DateAfter: str = "",
    DateBefore: str = "",
    Fields: str = "EventTime,Computer,Channel,Provider,EventID,EventData,Message",
) -> str:
    """
    Search Windows EVTX logs by channel, event ID, and date range.
    """
    if SearchRegex:
        IocRegex = SearchRegex
    if EventIDRegex:
        IdRegex = EventIDRegex
    if SearchVSS and not VSSAnalysisAge:
        VSSAnalysisAge = 30
    parameters = {
        "EvtxGlob": EvtxGlob,
        "IocRegex": IocRegex,
        "WhitelistRegex": WhitelistRegex,
        "PathRegex": PathRegex,
        "ChannelRegex": ChannelRegex,
        "ProviderRegex": ProviderRegex,
        "IdRegex": IdRegex,
        "VSSAnalysisAge": VSSAnalysisAge,
        "DateAfter": DateAfter,
        "DateBefore": DateBefore,
    }
    return _run_collection_tool(
        client_id,
        "Windows.EventLogs.EvtxHunter",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_logon_events(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Collect Windows logon session events.
    """
    return _run_collection_tool(
        client_id,
        "Windows.EventLogs.LogonSessions",
        None,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_powershell_scriptblock(
    client_id: str,
    org_id: str = "",
    SearchRegex: str = ".",
    DateAfter: str = "",
    DateBefore: str = "",
    Fields: str = "EventTime,Computer,EventID,EventData.ScriptBlockText,EventData.Path",
) -> str:
    """
    Search PowerShell script block logging events.
    """
    parameters = {
        "ChannelRegex": "Microsoft-Windows-PowerShell/Operational",
        "IdRegex": "4104",
        "IocRegex": SearchRegex,
        "DateAfter": DateAfter,
        "DateBefore": DateBefore,
    }
    return _run_collection_tool(
        client_id,
        "Windows.EventLogs.EvtxHunter",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_powershell_history(
    client_id: str,
    org_id: str = "",
    SearchRegex: str = ".",
    SearchStrings: str = "",
    StringWhiteList: str = "",
    UserRegex: str = ".",
    UploadFiles: bool = False,
    Fields: str = "*",
) -> str:
    """
    Collect PowerShell PSReadLine console history.
    """
    if SearchRegex != "." and not SearchStrings:
        SearchStrings = SearchRegex
    parameters = {
        "SearchStrings": SearchStrings,
        "StringWhiteList": StringWhiteList,
        "UserRegex": UserRegex,
        "UploadFiles": UploadFiles,
    }
    return _run_collection_tool(
        client_id,
        "Windows.System.Powershell.PSReadline",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_autoruns(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Collect Windows autorun/startup extension points.
    """
    return _run_collection_tool(client_id, "Windows.Sys.StartupItems", None, Fields, "", org_id)


@mcp.tool()
async def windows_wmi_persistence(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Detect WMI permanent event subscription persistence.
    """
    return _run_collection_tool(
        client_id,
        "Windows.Persistence.PermanentWMIEvents",
        None,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_rdp_sessions(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Collect Windows RDP authentication/session events.
    """
    return _run_collection_tool(client_id, "Windows.EventLogs.RDPAuth", None, Fields, "", org_id)


@mcp.tool()
async def windows_dns_cache(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Dump the Windows DNS client cache.
    """
    return _run_collection_tool(client_id, "Windows.System.DNSCache", None, Fields, "", org_id)


@mcp.tool()
async def windows_hash_search(
    client_id: str,
    org_id: str = "",
    Glob: str = "C:/**",
    SearchFilesGlob: str = "",
    SearchGlob: str = "",
    Upload_File: bool = False,
    YaraRule: str = "",
    Hash: str = "",
    HashRegex: str = "",
    Calculate_Hash: bool = False,
    MoreRecentThan: str = "",
    ModifiedBefore: str = "",
    VSS_MAX_AGE_DAYS: int = 0,
    UPLOAD_IS_RESUMABLE: bool = True,
    Fields: str = "*",
) -> str:
    """
    Search Windows files by glob or YARA rule using documented FileFinder params.
    """
    if SearchGlob:
        Glob = SearchGlob
    elif SearchFilesGlob:
        Glob = SearchFilesGlob
    if Hash or HashRegex:
        Calculate_Hash = True
    parameters = {
        "Glob": Glob,
        "Upload_File": Upload_File,
        "YaraRule": YaraRule,
        "Calculate_Hash": Calculate_Hash,
        "MoreRecentThan": MoreRecentThan,
        "ModifiedBefore": ModifiedBefore,
        "VSS_MAX_AGE_DAYS": VSS_MAX_AGE_DAYS,
        "UPLOAD_IS_RESUMABLE": UPLOAD_IS_RESUMABLE,
    }
    return _run_collection_tool(
        client_id,
        "Windows.Search.FileFinder",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_recycle_bin(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Parse Windows Recycle Bin metadata.
    """
    return _run_collection_tool(client_id, "Windows.Forensics.RecycleBin", None, Fields, "", org_id)


@mcp.tool()
async def windows_ntfs_mft(
    client_id: str,
    org_id: str = "",
    MFTDrive: str = "C:",
    Device: str = "",
    MFTPath: str = "",
    Accessor: str = "auto",
    AllNtfs: bool = False,
    PathRegex: str = ".",
    FileRegex: str = "^velociraptor\\.exe$",
    DateAfter: str = "",
    DateBefore: str = "",
    SizeMax: int = 0,
    Fields: str = "*"
) -> str:
    """
    Search MFT for filename or path on a Windows machine. This is a forensic collection and may return many rows. If failure retry with collect_artifact().
    Args:
        client_id: The Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        MFTDrive: Target drive letter (default is C:).
        FileRegex: Regex to match filenames or folders.
        PathRegex: Regex to match file paths (more costly).
        DateAfter: Filter for files modified/created after this timestamp.
        DateBefore: Filter for files modified/created before this timestamp.
        Fields: Comma-separated string of fields to return.

    Returns:
        A result string or error message.

    """
    artifact = "Windows.NTFS.MFT"
    result_scope = ""
    if Device:
        MFTDrive = Device
    parameters = {
        "MFTDrive": MFTDrive,
        "MFTPath": MFTPath,
        "Accessor": Accessor,
        "AllNtfs": AllNtfs,
        "PathRegex": PathRegex,
        "FileRegex": FileRegex,
        "DateAfter": DateAfter,
        "DateBefore": DateBefore,
        "SizeMax": SizeMax,
    }

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)


@mcp.tool()
async def windows_usn_journal(
    client_id: str,
    org_id: str = "",
    DriveLetter: str = "C:",
    Device: str = "",
    Accessor: str = "ntfs",
    MFTFile: str = "",
    USNFile: str = "",
    AllDrives: bool = False,
    FileNameRegex: str = ".",
    PathRegex: str = ".",
    MFT_ID_Regex: str = ".",
    Parent_MFT_ID_Regex: str = ".",
    DateAfter: str = "",
    DateBefore: str = "",
    FastPaths: bool = True,
    Fields: str = "Usn,Timestamp,Filename,FullPath,Reason,FileAttributes,SourceInfo",
) -> str:
    """
    Parse the Windows NTFS USN change journal.
    """
    if not Device:
        Device = DriveLetter
    parameters = {
        "Device": Device,
        "MFTFile": MFTFile,
        "USNFile": USNFile,
        "Accessor": Accessor,
        "AllDrives": AllDrives,
        "FileNameRegex": FileNameRegex,
        "PathRegex": PathRegex,
        "MFT_ID_Regex": MFT_ID_Regex,
        "Parent_MFT_ID_Regex": Parent_MFT_ID_Regex,
        "DateAfter": DateAfter,
        "DateBefore": DateBefore,
        "FastPaths": FastPaths,
    }
    return _run_collection_tool(
        client_id,
        "Windows.Forensics.Usn",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def windows_srum(
    client_id: str,
    org_id: str = "",
    Fields: str = "*",
) -> str:
    """
    Parse Windows SRUM resource usage data.
    """
    return _run_collection_tool(client_id, "Windows.Forensics.SRUM", None, Fields, "", org_id)


@mcp.tool()
async def windows_browser_history(
    client_id: str,
    org_id: str = "",
    URLRegex: str = ".",
    historyGlobs: str = "",
    urlSQLQuery: str = "",
    userRegex: str = ".",
    Fields: str = "URL,Title,LastVisitTime,VisitCount,TypedCount,BrowserType,User",
) -> str:
    """
    Collect Windows Chromium-family browser history.
    """
    parameters = {
        "historyGlobs": historyGlobs,
        "urlSQLQuery": urlSQLQuery,
        "userRegex": userRegex,
        "URLRegex": URLRegex,
    }
    return _run_collection_tool(
        client_id,
        "Windows.Applications.Chrome.History",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def yara_scan_files(
    client_id: str,
    YaraRule: str,
    org_id: str = "",
    FileNameRegex: str = ".",
    PathRegex: str = ".",
    DriveLetter: str = "C:",
    Fields: str = "*",
) -> str:
    """
    Scan Windows files with an inline YARA rule using raw NTFS access.
    """
    parameters = {
        "YaraRule": YaraRule,
        "FileNameRegex": FileNameRegex,
        "PathRegex": PathRegex,
        "DriveLetter": DriveLetter,
    }
    return _run_collection_tool(
        client_id,
        "Windows.Detection.Yara.NTFS",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def yara_scan_process(
    client_id: str,
    YaraRule: str,
    org_id: str = "",
    ProcessRegex: str = ".",
    PidRegex: str = ".",
    Fields: str = "*",
) -> str:
    """
    Scan Windows process memory with an inline YARA rule.
    """
    parameters = {
        "YaraRule": YaraRule,
        "ProcessRegex": ProcessRegex,
        "PidRegex": PidRegex,
    }
    return _run_collection_tool(
        client_id,
        "Windows.Detection.Yara.Process",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def linux_yara_scan(
    client_id: str,
    YaraRule: str,
    org_id: str = "",
    ProcessRegex: str = ".",
    PidRegex: str = ".",
    Fields: str = "*",
) -> str:
    """
    Scan Linux process memory with an inline YARA rule.
    """
    parameters = {
        "YaraRule": YaraRule,
        "ProcessRegex": ProcessRegex,
        "PidRegex": PidRegex,
    }
    return _run_collection_tool(
        client_id,
        "Linux.Detection.Yara.Process",
        parameters,
        Fields,
        "",
        org_id,
    )


@mcp.tool()
async def quarantine_host(client_id: str, org_id: str = "") -> str:
    """
    Quarantine a Windows host. Disabled unless ENABLE_DANGEROUS_TOOLS=true.
    """
    return _run_dangerous_collection(
        client_id,
        "Windows.Remediation.Quarantine",
        {"MessageBox": "Host quarantined by MCP automation."},
        org_id,
    )


@mcp.tool()
async def unquarantine_host(client_id: str, org_id: str = "") -> str:
    """
    Remove a Windows quarantine policy.
    """
    return _start_collection_tool(
        client_id,
        "Windows.Remediation.Quarantine",
        {"RemovePolicy": "Y"},
        org_id=org_id,
    )


@mcp.tool()
async def kill_process(client_id: str, pid: int, org_id: str = "") -> str:
    """
    Kill a remote process by PID. Disabled unless ENABLE_DANGEROUS_TOOLS=true.
    """
    return _run_dangerous_collection(
        client_id,
        "Generic.Utils.KillProcess",
        {"Pid": int(pid)},
        org_id,
    )


@mcp.tool()
async def collect_file(client_id: str, path: str, org_id: str = "") -> str:
    """
    Start a Generic.Collectors.File collection for a path or glob.
    """
    collection_spec = json.dumps([{"glob": path}])
    return _start_collection_tool(
        client_id,
        "Generic.Collectors.File",
        {"collectionSpec": collection_spec},
        org_id=org_id,
    )

@mcp.tool()
async def get_collection_results(
    client_id: str,
    flow_id: str,
    artifact: str,
    org_id: str = "",
    fields: str = "*",
    max_retries: int = 10,
    retry_delay: int = 30
) -> str:
    """
    Retrieve Velociraptor collection results for a given client, flow ID, and artifact.
    Waits and retries if the flow hasn't finished or if no results are immediately available.

    Args:
        client_id: The Velociraptor client ID.
        flow_id: The flow ID returned from the initial collection.
        artifact: The name of the artifact collected (e.g., Windows.NTFS.MFT).
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        fields: Comma-separated string of fields to return (default is "*").
        max_retries: Number of times to retry if the flow hasn't finished or no results yet.
        retry_delay: Time (in seconds) to wait between retries.

    Returns:
        Collection results as a string or an error message.
    """
    try:
        for attempt in range(max_retries):
            status = get_flow_status(client_id, flow_id, artifact, org_id=org_id)
            if status != "FINISHED":
                await asyncio.sleep(retry_delay)
                continue

            result = get_flow_results(client_id, flow_id, artifact, fields, org_id=org_id)
            return _json_success(result)
    except Exception as exc:
        return _json_error(str(exc))

    return _json_error("No results found after multiple retries or the flow did not finish.")


@mcp.tool()
async def collect_artifact(
    client_id: str,
    artifact: str,
    org_id: str = "",
    parameters: ArtifactParameters | None = None,
    legacy_parameters: str = "",
) -> str:
    """
    Start a Velociraptor artifact collection and return the resulting flow metadata.

    Args:
        client_id: Velociraptor client ID to target.
        artifact: Name of the Velociraptor artifact to collect.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.
        parameters: Structured artifact parameters as a JSON object with
            scalar values or lists of scalar values.
        legacy_parameters: Backward-compatible string format limited to simple
            scalar assignments or list literals like
            "PathRegex='.*',Targets=['_BasicCollection']". Do not pass raw
            VQL fragments.

    Returns:
        Flow metadata for the started collection.
    """
    if parameters is not None and legacy_parameters.strip():
        return _json_error(
            "Provide either 'parameters' or 'legacy_parameters', not both."
        )

    try:
        parsed_parameters = parameters
        if legacy_parameters.strip():
            parsed_parameters = _parse_collection_parameters(legacy_parameters)
        elif parameters is not None:
            parsed_parameters = {
                key: normalize_parameter_value(value)
                for key, value in parameters.items()
            }
    except Exception as exc:
        return _json_error(str(exc))
    return _start_collection_tool(client_id, artifact, parsed_parameters, org_id=org_id)


@mcp.tool()
async def collect_forensic_triage(
    client_id: str,
    org_id: str = "",
) -> str:
    """
    Start a Windows.Triage.Targets basic triage collection and return flow metadata.

    Args:
        client_id: Velociraptor client ID.
        org_id: Optional Velociraptor org ID for multi-tenant deployments.

    Returns:
        Flow metadata for the started collection.
    """
    artifact = "Windows.Triage.Targets"
    parameters = {"Targets": '["_BasicCollection"]'}
    timeout = 2400

    return _start_collection_tool(
        client_id,
        artifact,
        parameters,
        timeout=timeout,
        org_id=org_id,
    )

@mcp.tool()
async def list_windows_artifacts(org_id: str = "") -> str:
    """
    Finds Availible Windows artifacts. 

    Generally paramaters that target filename regexs are more performant in NTFS queries: MFT, USN and can also be used to target top level folders.
    A Path glob is performant, and path regex is useful to specifically filter locations.
    """
    return _run_json_tool(_summarize_artifacts, "^windows\\.", org_id)

@mcp.tool()
async def list_linux_artifacts(org_id: str = "") -> str:
    """
    Finds Availible Linux artifacts. 

    """
    return _run_json_tool(_summarize_artifacts, "linux\\.", org_id)


@mcp.tool()
async def list_macos_artifacts(org_id: str = "") -> str:
    """
    Finds available macOS artifacts.
    """
    return _run_json_tool(_summarize_artifacts, "macos\\.", org_id)


if __name__ == "__main__":
    mcp.run()
