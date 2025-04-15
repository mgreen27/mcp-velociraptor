'''
Expecting to print out server info() if API working as expected
{
    "Hostname": "vr",
    "Uptime": 46570,
    "BootTime": 1743261689,
    "OS": "linux",
    "Platform": "ubuntu",
    "PlatformFamily": "debian",
    "PlatformVersion": "24.04",
    "KernelVersion": "6.8.0-56-generic",
    "VirtualizationSystem": "",
    "VirtualizationRole": "",
    "CompilerVersion": "go1.23.2",
    "HostID": "1c38feaf-a3d0-41d0-ad3b-00228390771f",
    "Exe": "/usr/local/bin/velociraptor.bin",
    "CWD": "/",
    "IsAdmin": false,
    "ClientStart": "2025-03-29T07:54:43.47676618Z",
    "LocalTZ": "UTC",
    "LocalTZOffset": 0,
    "Fqdn": "vr",
    "Architecture": "amd64"
}
'''

import yaml, grpc, json
from pyvelociraptor import api_pb2, api_pb2_grpc

config = yaml.safe_load(open("api_client.yaml"))

# Prepare gRPC channel credentials
creds = grpc.ssl_channel_credentials(
    root_certificates=config["ca_certificate"].encode("utf-8"),
    private_key=config["client_private_key"].encode("utf-8"),
    certificate_chain=config["client_cert"].encode("utf-8")
)
channel_opts = (('grpc.ssl_target_name_override', "VelociraptorServer"),)
channel = grpc.secure_channel(config["api_connection_string"], creds, options=channel_opts)
stub = api_pb2_grpc.APIStub(channel)

vql = 'SELECT * FROM info()'
request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=vql)])

print(f'\nExpecting to print out server info() if API working as expected')
for response in stub.Query(request):
    if response.Response:
        rows = json.loads(response.Response)
        for line in rows:
            print(json.dumps(line, indent=4))

