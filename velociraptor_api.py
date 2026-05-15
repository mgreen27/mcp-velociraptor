import json
import os
import sys
from pathlib import Path

import grpc
import yaml
from pyvelociraptor import api_pb2, api_pb2_grpc

stub = None
DEFAULT_ORG_ID = os.environ.get("VELOCIRAPTOR_ORG_ID", "").strip()

def resolve_config_path(config_path: str | None = None) -> Path:
    explicit_path = config_path or os.environ.get("VELOCIRAPTOR_API_CONFIG")
    if explicit_path:
        resolved = Path(explicit_path).expanduser()
        if resolved.is_file():
            return resolved
        raise FileNotFoundError(
            f"Velociraptor API config not found: {resolved}. "
            "Set VELOCIRAPTOR_API_CONFIG to a valid file path."
        )

    candidates = [
        Path("api_client.yaml"),
        Path.home() / ".config" / "api_client.yaml",
    ]
    for candidate in candidates:
        resolved = candidate.expanduser()
        if resolved.is_file():
            return resolved

    raise FileNotFoundError(
        "Velociraptor API config not found. Checked ./api_client.yaml and "
        "~/.config/api_client.yaml. Set VELOCIRAPTOR_API_CONFIG to override."
    )


def init_stub(config_path: str | None = None):
    global stub
    resolved_path = resolve_config_path(config_path)
    config = yaml.safe_load(resolved_path.read_text())
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf-8"),
        private_key=config["client_private_key"].encode("utf-8"),
        certificate_chain=config["client_cert"].encode("utf-8")
    )
    channel_opts = (('grpc.ssl_target_name_override', "VelociraptorServer"),)
    channel = grpc.secure_channel(config["api_connection_string"], creds, options=channel_opts)
    stub = api_pb2_grpc.APIStub(channel)


def resolve_org_id(org_id: str | None = None) -> str | None:
    resolved = (org_id or DEFAULT_ORG_ID).strip()
    return resolved or None


def run_vql_query(vql: str, org_id: str | None = None):
    if stub is None:
        raise RuntimeError("Stub not initialized. Call init_stub() first.")
    request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=vql)])
    resolved_org_id = resolve_org_id(org_id)
    if resolved_org_id:
        request.org_id = resolved_org_id
    results = []
    print(request, file=sys.stderr)
    
    for resp in stub.Query(request):
        if hasattr(resp, "error") and resp.error:
            raise RuntimeError(f"Velociraptor API error: {resp.error}")
        if hasattr(resp, "Response") and resp.Response:
            results.extend(json.loads(resp.Response))
    return results


def find_client_info(hostname: str, org_id: str | None = None, search_all_orgs: bool = False) -> dict:
    escaped_hostname = hostname.replace("\\", "\\\\").replace("'", "\\'")
    resolved_org_id = resolve_org_id(org_id)

    select_clause = (
        "SELECT client_id,"
        "timestamp(epoch=first_seen_at) as FirstSeen,"
        "timestamp(epoch=last_seen_at) as LastSeen,"
        "os_info.hostname as Hostname,"
        "os_info.fqdn as Fqdn,"
        "os_info.system as OSType,"
        "os_info.release as OS,"
        "os_info.machine as Machine,"
        "agent_information.version as AgentVersion "
    )
    where_clause = (
        f"WHERE os_info.hostname =~ '^{escaped_hostname}$' "
        f"OR os_info.fqdn =~ '^{escaped_hostname}$'"
    )

    if search_all_orgs and not resolved_org_id:
        vql = (
            "SELECT OrgId, Name as OrgName, client_id, FirstSeen, LastSeen, Hostname, "
            "Fqdn, OSType, OS, Machine, AgentVersion "
            "FROM foreach( "
            "row={ SELECT OrgId, Name FROM orgs() }, "
            "query={ "
            "SELECT OrgId, OrgName, client_id, FirstSeen, LastSeen, Hostname, "
            "Fqdn, OSType, OS, Machine, AgentVersion "
            "FROM query( "
            "query={ "
            f"{select_clause} FROM clients() {where_clause} "
            "ORDER BY LastSeen DESC LIMIT 1 "
            "}, "
            "org_id=OrgId "
            ") "
            "} "
            ") ORDER BY LastSeen DESC LIMIT 1"
        )
    else:
        vql = (
            f"{select_clause} "
            f"FROM clients() {where_clause} "
            "ORDER BY LastSeen DESC LIMIT 1"
        )

    result = run_vql_query(vql, org_id=resolved_org_id)
    if not result:
        return None
    row = result[0]
    if resolved_org_id and "OrgId" not in row:
        row["OrgId"] = resolved_org_id
    return row


def realtime_collection(
    client_id: str,
    artifact: str,
    parameters: str = "",
    fields: str = "*",
    result_scope: str = "",
    org_id: str | None = None,
) -> str:
    vql = (
        f"LET collection <= collect_client(urgent='TRUE',client_id='{client_id}', artifacts='{artifact}', env=dict({parameters})) "
        f"LET get_monitoring = SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId = collection.flow_id LIMIT 1 "
        f"LET get_results = SELECT * FROM source(client_id=collection.request.client_id, flow_id=collection.flow_id,artifact='{artifact}{result_scope}') "
        f"SELECT {fields} FROM foreach(row= get_monitoring ,query= get_results) "
        )

    try:
        results = run_vql_query(vql, org_id=org_id)
    except Exception as e:
        return f"Error starting collection: {e}"

    return str(results)

def start_collection(
    client_id: str,
    artifact: str,
    parameters: str = "",
    org_id: str | None = None,
) -> str:
    vql = (
        f"LET collection <= collect_client(urgent='TRUE',client_id='{client_id}', artifacts='{artifact}', env=dict({parameters})) "
        f" SELECT flow_id,request.artifacts as artifacts,request.specs[0] as specs FROM foreach(row= collection) "
        )

    try:
        results = run_vql_query(vql, org_id=org_id)
        return results
    except Exception as e:
        return f"Error starting collection: {e}"


def get_flow_status(client_id: str, flow_id: str, artifact: str, org_id: str | None = None) -> str:
    vql = (
        f"SELECT * FROM flow_logs(client_id='{client_id}', flow_id='{flow_id}') "
        f"WHERE message =~ '^Collection {artifact} is done after'"
        f"LIMIT 100"
    )

    try:
        results = run_vql_query(vql, org_id=org_id)
    except Exception as e:
        return f"Error checking flow status: {e}"

    if results and isinstance(results, list) and len(results) > 0:
        return "FINISHED"

    return "RUNNING"


def get_flow_results(
    client_id: str,
    flow_id: str,
    artifact: str,
    fields: str = "*",
    org_id: str | None = None,
) -> str:
    vql = (
        f"SELECT {fields} FROM source(client_id='{client_id}', flow_id='{flow_id}',artifact='{artifact}') "
    )

    try:
        results = run_vql_query(vql, org_id=org_id)
        return results
    except Exception as e:
        return f"Error checking flow status: {e}"


def list_orgs() -> list[dict]:
    try:
        return run_vql_query("SELECT OrgId, Name, Nonce FROM orgs()")
    except Exception as e:
        return [{"error": f"Failed to list orgs: {str(e)}"}]
