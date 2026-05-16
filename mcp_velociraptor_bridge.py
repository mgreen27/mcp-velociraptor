from mcp.server.fastmcp import FastMCP

import os
import asyncio
import ast
import json
import re
from velociraptor_api import *


mcp = FastMCP("velociraptor-mcp")

# Resolve the API client config from VELOCIRAPTOR_API_CONFIG, ./api_client.yaml,
# or ~/.config/api_client.yaml.
init_stub(os.environ.get("VELOCIRAPTOR_API_CONFIG"))
api_list_orgs = list_orgs

ArtifactParameters = dict[str, ParameterValue]


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
async def windows_ntfs_mft(
    client_id: str,
    org_id: str = "",
    MFTDrive: str = "C:",
    PathRegex: str = ".",
    FileRegex: str = "^velociraptor\\.exe$",
    DateAfter: str = "",
    DateBefore: str = "",
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
    parameters = {
        "MFTDrive": MFTDrive,
        "PathRegex": PathRegex,
        "FileRegex": FileRegex,
        "DateAfter": DateAfter,
        "DateBefore": DateBefore,
    }

    return _run_collection_tool(client_id, artifact, parameters, Fields, result_scope, org_id)

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


if __name__ == "__main__":
    mcp.run()
