import yaml, grpc, json
from pyvelociraptor import api_pb2, api_pb2_grpc
from velociraptor_api import *

stub = None

def init_stub(config_path):
    global stub
    config = yaml.safe_load(open(config_path))
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf-8"),
        private_key=config["client_private_key"].encode("utf-8"),
        certificate_chain=config["client_cert"].encode("utf-8")
    )
    channel_opts = (('grpc.ssl_target_name_override', "VelociraptorServer"),)
    channel = grpc.secure_channel(config["api_connection_string"], creds, options=channel_opts)
    stub = api_pb2_grpc.APIStub(channel)


def run_vql_query(vql: str):
    if stub is None:
        raise RuntimeError("Stub not initialized. Call init_stub() first.")
    request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=vql)])
    results = []
    print(request)
    
    for resp in stub.Query(request):
        if hasattr(resp, "error") and resp.error:
            raise RuntimeError(f"Velociraptor API error: {resp.error}")
        if hasattr(resp, "Response") and resp.Response:
            results.extend(json.loads(resp.Response))
    return results


def find_client_info(hostname: str) -> dict:
    vql = (
        f"SELECT client_id,"
        "timestamp(epoch=first_seen_at) as FirstSeen,"
        "timestamp(epoch=last_seen_at) as LastSeen,"
        "os_info.hostname as Hostname,"
        "os_info.fqdn as Fqdn,"
        "os_info.system as OSType,"
        "os_info.release as OS,"
        "os_info.machine as Machine,"
        "agent_information.version as AgentVersion "
        f"FROM clients() WHERE os_info.hostname =~ '^{hostname}$' OR os_info.fqdn =~ '^{hostname}$' ORDER BY LastSeen DESC LIMIT 1" 
        )

    result = run_vql_query(vql)
    if not result:
        return None
    return result[0]


def realtime_collection(client_id: str, artifact: str, parameters: str = "", fields: str = "*", result_scope: str = "") -> str:
    vql = (
        f"LET collection <= collect_client(urgent='TRUE',client_id='{client_id}', artifacts='{artifact}', env=dict({parameters})) "
        f"LET get_monitoring = SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId = collection.flow_id LIMIT 1 "
        f"LET get_results = SELECT * FROM source(client_id=collection.request.client_id, flow_id=collection.flow_id,artifact='{artifact}{result_scope}') "
        f"SELECT {fields} FROM foreach(row= get_monitoring ,query= get_results) "
        )

    try:
        results = run_vql_query(vql)
    except Exception as e:
        return f"Error starting collection: {e}"

    return str(results)

def start_collection(client_id: str, artifact: str, parameters: str = "" ) -> str:
    vql = (
        f"LET collection <= collect_client(urgent='TRUE',client_id='{client_id}', artifacts='{artifact}', env=dict({parameters})) "
        f" SELECT flow_id,request.artifacts as artifacts,request.specs[0] as specs FROM foreach(row= collection) "
        )

    try:
        results = run_vql_query(vql)
        return results
    except Exception as e:
        return f"Error starting collection: {e}"


def get_flow_status(client_id: str, flow_id: str, artifact: str) -> str:
    vql = (
        f"SELECT * FROM flow_logs(client_id='{client_id}', flow_id='{flow_id}') "
        f"WHERE message =~ '^Collection {artifact} is done after'"
        f"LIMIT 100"
    )

    try:
        results = run_vql_query(vql)
    except Exception as e:
        return f"Error checking flow status: {e}"

    if results and isinstance(results, list) and len(results) > 0:
        return "FINISHED"

    return "RUNNING"


def get_flow_results(client_id: str, flow_id: str, artifact: str, fields: str = "*" ) -> str:
    vql = (
        f"SELECT {fields} FROM source(client_id='{client_id}', flow_id='{flow_id}',artifact='{artifact}') "
    )

    try:
        results = run_vql_query(vql)
        return results
    except Exception as e:
        return f"Error checking flow status: {e}"
