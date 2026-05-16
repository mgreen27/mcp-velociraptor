import json
import os
import re
import sys
from pathlib import Path
from typing import Mapping

import grpc
import yaml
from pyvelociraptor import api_pb2, api_pb2_grpc

stub = None
DEFAULT_ORG_ID = os.environ.get("VELOCIRAPTOR_ORG_ID", "").strip()
VALID_PARAMETER_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
VALID_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
VALID_ARTIFACT_RE = re.compile(r"^[A-Za-z0-9_.:/-]+$")
ScalarParameter = str | int | float | bool | None
ParameterValue = ScalarParameter | list[ScalarParameter]
SCALAR_PARAMETER_TYPES = (str, int, float, bool)


def vql_literal(value: ParameterValue) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(vql_literal(item) for item in value) + "]"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)

    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def normalize_parameter_value(value) -> ParameterValue:
    if value is None or isinstance(value, SCALAR_PARAMETER_TYPES):
        return value
    if isinstance(value, list):
        normalized_items = []
        for item in value:
            if isinstance(item, list):
                raise ValueError(
                    "Parameter lists must contain scalar values only."
                )
            normalized_items.append(normalize_parameter_value(item))
        return normalized_items
    raise ValueError(
        "Parameter values must be JSON scalars or lists of scalar values."
    )


def normalize_fields(fields: str) -> str:
    cleaned = fields.strip()
    if not cleaned:
        raise ValueError("Fields must not be empty.")
    if cleaned == "*":
        return cleaned

    result = []
    for field in cleaned.split(","):
        candidate = field.strip()
        if not candidate or not VALID_FIELD_RE.fullmatch(candidate):
            raise ValueError(
                "Invalid field selection. Use '*' or a comma-separated list of field "
                "names such as 'Pid, Name, CommandLine'."
            )
        result.append(candidate)

    return ", ".join(result)


def normalize_artifact_name(artifact: str) -> str:
    cleaned = artifact.strip()
    if not cleaned or not VALID_ARTIFACT_RE.fullmatch(cleaned):
        raise ValueError(f"Invalid artifact name: {artifact!r}")
    return cleaned


def normalize_env_dict(parameters: Mapping[str, ParameterValue] | None = None) -> str:
    if parameters is None:
        return ""
    if not isinstance(parameters, Mapping):
        raise TypeError("parameters must be a mapping or None")

    items = []
    for key, value in parameters.items():
        if not VALID_PARAMETER_NAME_RE.fullmatch(key):
            raise ValueError(f"Invalid parameter name: {key!r}")
        normalized_value = normalize_parameter_value(value)
        items.append(f"{key}={vql_literal(normalized_value)}")

    return ",".join(items)

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
    hostname_pattern = f"^{re.escape(hostname)}$"
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
        f"WHERE os_info.hostname =~ {vql_literal(hostname_pattern)} "
        f"OR os_info.fqdn =~ {vql_literal(hostname_pattern)}"
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
    parameters: Mapping[str, ParameterValue] | None = None,
    fields: str = "*",
    result_scope: str = "",
    org_id: str | None = None,
) -> list[dict]:
    normalized_artifact = normalize_artifact_name(artifact)
    normalized_result_artifact = normalize_artifact_name(f"{artifact}{result_scope}")
    normalized_fields = normalize_fields(fields)
    normalized_parameters = normalize_env_dict(parameters)
    vql = (
        f"LET collection <= collect_client(urgent='TRUE',client_id={vql_literal(client_id)}, "
        f"artifacts={vql_literal(normalized_artifact)}, env=dict({normalized_parameters})) "
        f"LET get_monitoring = SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId = collection.flow_id LIMIT 1 "
        f"LET get_results = SELECT * FROM source(client_id=collection.request.client_id, flow_id=collection.flow_id,artifact={vql_literal(normalized_result_artifact)}) "
        f"SELECT {normalized_fields} FROM foreach(row=get_monitoring, query=get_results) "
    )

    return run_vql_query(vql, org_id=org_id)

def start_collection(
    client_id: str,
    artifact: str,
    parameters: Mapping[str, ParameterValue] | None = None,
    timeout: int | None = None,
    org_id: str | None = None,
) -> list[dict]:
    normalized_artifact = normalize_artifact_name(artifact)
    normalized_parameters = normalize_env_dict(parameters)
    timeout_arg = ""
    if timeout is not None:
        timeout_arg = f", timeout={int(timeout)}"
    vql = (
        f"LET collection <= collect_client(urgent='TRUE',client_id={vql_literal(client_id)}, "
        f"artifacts={vql_literal(normalized_artifact)}, env=dict({normalized_parameters}){timeout_arg}) "
        "SELECT flow_id, request.artifacts as artifacts, request.timeout as timeout, "
        "request.specs[0] as specs FROM foreach(row=collection) "
    )

    return run_vql_query(vql, org_id=org_id)


def get_flow_status(client_id: str, flow_id: str, artifact: str, org_id: str | None = None) -> str:
    artifact_pattern = f"^Collection {re.escape(normalize_artifact_name(artifact))} is done after"
    vql = (
        f"SELECT * FROM flow_logs(client_id={vql_literal(client_id)}, flow_id={vql_literal(flow_id)}) "
        f"WHERE message =~ {vql_literal(artifact_pattern)} "
        "LIMIT 100"
    )

    results = run_vql_query(vql, org_id=org_id)

    if results and isinstance(results, list) and len(results) > 0:
        return "FINISHED"

    return "RUNNING"


def get_flow_results(
    client_id: str,
    flow_id: str,
    artifact: str,
    fields: str = "*",
    org_id: str | None = None,
) -> list[dict]:
    normalized_artifact = normalize_artifact_name(artifact)
    normalized_fields = normalize_fields(fields)
    vql = (
        f"SELECT {normalized_fields} FROM source(client_id={vql_literal(client_id)}, "
        f"flow_id={vql_literal(flow_id)},artifact={vql_literal(normalized_artifact)}) "
    )

    return run_vql_query(vql, org_id=org_id)


def list_orgs() -> list[dict]:
    return run_vql_query("SELECT OrgId, Name, Nonce FROM orgs()")
