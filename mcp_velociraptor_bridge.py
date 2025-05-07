from mcp.server.fastmcp import FastMCP

import yaml, grpc, json
from pyvelociraptor import api_pb2, api_pb2_grpc
from velociraptor_api import *
import asyncio


mcp = FastMCP("velociraptor-mcp")

# add api config path - wrong config and MCP connection will fail
api_client_config = "/path/to/api_client.yaml"
init_stub(api_client_config)

    
@mcp.tool()
def client_info(hostname: str) -> dict:
    """
    Retrieve client information from the Velociraptor server.

    Args:
        hostname: Hostname or FQDN of the target endpoint.

    Returns:
        A dictionary containing client metadata, including the client_id,
        which can be used to target other artifact collections.
    """
    return find_client_info(hostname)

@mcp.tool()
async def windows_pslist(
    client_id: str,
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
    parameters = (
        f"ProcessRegex='{ProcessRegex}',"
        f"PidRegex='{PidRegex}',"
        f"ExePathRegex='{ExePathRegex}',"
        f"CommandLineRegex='{CommandLineRegex}',"
        f"UsernameRegex='{UsernameRegex}'"
    )

    return realtime_collection(client_id,artifact,parameters,Fields,result_scope)

@mcp.tool()
async def windows_netstat_enriched(
    client_id: str,
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
    parameters = (
        f"IPRegex='{IPRegex}',"
        f"PortRegex='{PortRegex}',"
        f"ProcessNameRegex='{ProcessNameRegex}',"
        f"ProcessPathRegex='{ProcessPathRegex}',"
        f"CommandLineRegex='{CommandLineRegex}',"
        f"UsernameRegex='{UsernameRegex}'"
    )

    return realtime_collection(client_id,artifact,parameters,Fields,result_scope)


@mcp.tool()
async def windows_scheduled_tasks(
    client_id: str,
    Fields: str = "OSPath,Mtime,Command,ExpandedCommand,Arguments,ComHandler,UserId,StartBoundary,Authenticode"
) -> str:
    """
    List scheduled tasks (persistance) with metadata on a Windows host

    Args:
        client_id: Velociraptor client ID.
        Fields: Comma-separated list of fields to return.

    Returns:
        Scheduled task results as a string or error message.
    """
    artifact = "Windows.System.TaskScheduler"
    result_scope = "/Analysis"
    parameters = ""  # No parameters for this artifact

    return realtime_collection(client_id, artifact, parameters, Fields, result_scope)

## Evidence of execution
@mcp.tool()
async def windows_execution_amcache(
    client_id: str,
    Fields: str = "FullPath,SHA1,ProgramID,FileDescription,FileVersion,Publisher,CompileTime,LastModified,LastRunTime"
) -> str:
    """
    Collect evidence of execution from Amcache on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        Fields: Comma-separated list of fields to return.

    Returns:
        Amcache artifact results as a string or error message.
    """
    artifact = "Windows.Detection.Amcache"
    result_scope = ""
    parameters = ""  # No parameters for this artifact

    return realtime_collection(client_id, artifact, parameters, Fields, result_scope)


@mcp.tool()
async def windows_execution_bam(
    client_id: str,
    Fields: str = "*"
) -> str:
    """
    Extract evidence of execution from the BAM (Background Activity Moderator) registry key on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        Fields: Comma-separated list of fields to return.

    Returns:
        BAM artifact results as a string or error message.
    """
    artifact = "Windows.Forensics.Bam"
    result_scope = ""
    parameters = ""  # No parameters for this artifact

    return realtime_collection(client_id, artifact, parameters, Fields, result_scope)

@mcp.tool()
async def windows_execution_activitiesCache(
    client_id: str,
    Fields: str = "*"
) -> str:
    """
    Evidence of execution from activitiesCache.db (windows timeline) of system activity on a Windows host.

    Args:
        client_id: Velociraptor client ID.
        Fields: Comma-separated list of fields to return.

    Returns:
        Timeline artifact results as a string or error message.
    """
    artifact = "Windows.Forensics.Timeline"
    result_scope = ""
    parameters = ""  # No parameters for this artifact

    return realtime_collection(client_id, artifact, parameters, Fields, result_scope)

@mcp.tool()
async def windows_execution_userassist(
    client_id: str,
    Fields: str = "Name,User,LastExecution,NumberOfExecutions"
) -> str:
    """
    Extract evidence of execution from UserAssist registry keys.

    Args:
        client_id: Velociraptor client ID.
        Fields: Comma-separated list of fields to return.

    Returns:
        UserAssist artifact results as a string or error message.
    """
    artifact = "Windows.Registry.UserAssist"
    result_scope = ""
    parameters = ""  # No parameters for this artifact

    return realtime_collection(client_id, artifact, parameters, Fields, result_scope)

@mcp.tool()
async def windows_execution_shimcache(
    client_id: str,
    Fields: str = "Position,ModificationTime,Path,ExecutionFlag,ControlSet"
) -> str:
    """
    Parse ShimCache (AppCompatCache) entries from the registry on a Windows host.

    Note:
        Presence of a ShimCache entry may not indicate actual execution—only that the file was accessed or observed by the system.

    Args:
        client_id: Velociraptor client ID.
        Fields: Comma-separated list of fields to return.

    Returns:
        ShimCache (AppCompatCache) artifact results as a string or error message.
    """
    artifact = "Windows.Registry.AppCompatCache"
    result_scope = ""
    parameters = ""  # No parameters for this artifact

    return realtime_collection(client_id, artifact, parameters, Fields, result_scope)


@mcp.tool()
async def windows_execution_prefetch(
    client_id: str,
    Fields: str = "Binary,CreationTime,LastRunTimes,RunCount,Hash" 
    #"Executable,LastRunTimes,RunCount,PrefetchFileName,Version,Hash,CreationTime,ModificationTime,Binary"
) -> str:
    """
    Parse Prefetch files on a Windows host to identify previously executed programs.

    Args:
        client_id: Velociraptor client ID.
        Fields: Comma-separated list of fields to return.

    Returns:
        Prefetch artifact results as a string or error message.
    """
    artifact = "Windows.Forensics.Prefetch"
    result_scope = ""
    parameters = ""  # No parameters for this artifact

    return realtime_collection(client_id, artifact, parameters, Fields, result_scope)


@mcp.tool()
async def windows_ntfs_mft(
    client_id: str,
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
    parameters = (
        f"MFTDrive='{MFTDrive}',"
        f"PathRegex='{PathRegex}',"
        f"FileRegex='{FileRegex}',"
        f"DateAfter='{DateAfter}',"
        f"DateBefore='{DateBefore}'"
    )

    return realtime_collection(client_id, artifact, parameters, Fields, result_scope)

@mcp.tool()
async def get_collection_results(
    client_id: str,
    flow_id: str,
    artifact: str,
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
        fields: Comma-separated string of fields to return (default is "*").
        max_retries: Number of times to retry if the flow hasn't finished or no results yet.
        retry_delay: Time (in seconds) to wait between retries.

    Returns:
        Collection results as a string or an error message.
    """
    for attempt in range(max_retries):
        status = get_flow_status(client_id, flow_id, artifact)
        if status != "FINISHED":
            await asyncio.sleep(retry_delay)
            continue

        result = get_flow_results(client_id, flow_id, artifact, fields)
        return result

    return "No results found after multiple retries or the flow did not finish."


@mcp.tool()
async def collect_artifact(
    client_id: str,
    artifact: str,
    parameters: str = ""
) -> str:
    """
    Start a Velociraptor artifact collection and wait for results (up to 10 minutes).

    Args:
        client_id: Velociraptor client ID to target.
        artifact: Name of the Velociraptor artifact to collect.
        parameters: A comma-separated string of key='value' pairs to pass to the artifact.
        fields: Comma-separated fields to return.
        check_interval: Number of seconds to wait before checking for results again.
        timeout: Maximum number of seconds to wait for the collection to complete.

    Returns:
        The collection results or the initial collection output if it times out.
    """

    # Start the collection
    response = start_collection(client_id, artifact, parameters)

    # Ensure the response contains the flow ID
    if not isinstance(response, list) or not response or "flow_id" not in response[0]:
        return f"Failed to start collection: {response}"

    return response[0]


@mcp.tool()
async def collect_forensic_triage(
    client_id: str,
    Fields: str = "*"
) -> str:
    """
    Collect forensic triage files using the Windows.KapeFiles.Targets artifact.

    Args:
        client_id: Velociraptor client ID.
        Fields: Comma-separated list of fields to return (default is '*').

    Returns:
        Collection results or flow metadata.
    """
    artifact = "Windows.KapeFiles.Targets"
    parameters = "_BasicCollection='Y'"

    return start_collection(client_id, artifact, parameters, Fields)

@mcp.tool()
async def list_windows_artifacts() -> list[dict]:
    """
    Finds Availible Windows artifacts. 

    Generally paramaters that target filename regexs are more performant in NTFS queries: MFT, USN and can also be used to target top level folders.
    A Path glob is performant, and path regex is useful to specifically filter locations.
    """
    vql = """
    LET params(data) = SELECT name FROM data
    SELECT name, description, params(data=parameters) AS parameters
    FROM artifact_definitions()
    WHERE type =~ 'client' AND name =~ '^windows\\.'
    """

    def shorten(desc: str) -> str:
        return desc.strip().split(".")[0][:120].rstrip() + "..." if desc else ""

    try:
        results = run_vql_query(vql)
        summaries = []
        for r in results:
            summaries.append({
                "name": r["name"],
                "short_description": shorten(r.get("description", "")),
                "parameters": [p["name"] for p in r.get("parameters", [])]
            })
        return summaries
    except Exception as e:
        return [{"error": f"Failed to summarize artifact definitions: {str(e)}"}]


if __name__ == "__main__":
    mcp.run()
