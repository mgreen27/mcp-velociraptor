# Velociraptor MCP
Velociraptor MCP is a POC Model Context Protocol bridge for exposing LLMs to MCP clients.

Initial version has several Windows orientated triage tools deployed. Best use is querying usecase to target machine name.

e.g 

`can you give me all network connections on MACHINENAME and look for suspicious processes?`

`can you tell me which artifacts target the USN journal`




## Installation
### 1. Setup an API account
https://docs.velociraptor.app/docs/server_automation/server_api/

Generate an api config file:

`velociraptor --config /etc/velociraptor/server.config.yaml config api_client --name api --role administrator,api api_client.yaml`

### 2. Clone mcp-velociraptor repo and test API

- Copy `api_client.yaml` to the repo root, or keep it anywhere local and set `VELOCIRAPTOR_API_CONFIG=/path/to/api_client.yaml`.
- Copy `example.env` to `.env` for local development, then set `VELOCIRAPTOR_API_CONFIG` to your real `api_client.yaml` path. The bridge, smoke script, and agent load dotenv config automatically without overriding variables already supplied by your shell or MCP client.
- `api_client.yaml` is gitignored and should not be committed.
- Run `.venv/bin/python test_api.py` to confirm the API works when `.env` is configured, or use `VELOCIRAPTOR_API_CONFIG=/path/to/api_client.yaml .venv/bin/python test_api.py` to override it for a single run.
- The MCP bridge reads the same `VELOCIRAPTOR_API_CONFIG` environment variable after loading dotenv config.
- For multi-tenant deployments, optionally set `VELOCIRAPTOR_ORG_ID` to choose a default org context.
- Set `VELOCIRAPTOR_DEBUG_VQL=1` only when you want raw VQL request logging on stderr for debugging.
- Set `ENABLE_DANGEROUS_TOOLS=true` only when you explicitly want to enable raw VQL, quarantine, and remote process-kill tools.

### 3. Connect to MCP client of choice

The easiest configuration is to run your venv python directly calling
`mcp_velociraptor_bridge.py`. You can either put values directly in the MCP
client config:

```json
{
  "mcpServers": {
    "velociraptor": {
      "command": "/path/to/venv/bin/python",
      "env": {
        "VELOCIRAPTOR_API_CONFIG": "/path/to/api_client.yaml",
        "VELOCIRAPTOR_ORG_ID": "O123"
      },
      "args": [
        "/path/to/mcp_velociraptor_bridge.py"
      ]
    }
  }
}
```

Or point the MCP client at a dotenv file:

```json
{
  "mcpServers": {
    "velociraptor": {
      "command": "/path/to/venv/bin/python",
      "env": {
        "VELOCIRAPTOR_ENV_FILE": "/path/to/mcp-velociraptor/.env"
      },
      "args": [
        "/path/to/mcp_velociraptor_bridge.py"
      ]
    }
  }
}
```

Config precedence is: direct environment values from the MCP client or shell,
then `VELOCIRAPTOR_ENV_FILE` if set, then repo-local `.env`, then fallback
paths such as `./api_client.yaml` and `~/.config/api_client.yaml`.

The separate agent proof-of-concept now lives under `agent_poc/`. It now
includes a Windows-first engagement manager that fans out to isolated process,
network, persistence, and execution analysts in parallel, with deterministic
evidence collection and model-only synthesis per role. See
`agent_poc/README.md` for agent-specific usage and automation examples,
including verbose collection progress output with artifact names and row counts.

### 4. Tool Response Format

MCP tool responses are emitted as JSON text envelopes so stdio clients do not
need to parse Python `repr()` output:

```json
{"ok": true, "data": {...}}
```

or

```json
{"ok": false, "error": "message"}
```

`collect_artifact` accepts `parameters` as a structured JSON object with scalar
values or lists of scalar values, for example
`{"PathRegex": ".*", "Targets": ["_BasicCollection"]}`. Legacy compatibility
input can be supplied via `legacy_parameters` with simple scalar assignments or
list literals such as `PathRegex='.*',Targets=['_BasicCollection']`; raw VQL
fragments are no longer passed through.
`collect_forensic_triage` wraps `Windows.Triage.Targets` with
`Targets='["_BasicCollection"]'` and a collection timeout of `2400` seconds.

### 5. Tool Inventory

The bridge now exposes the original Windows/Linux triage tools plus expanded
fleet, Linux, macOS, Windows, YARA, and response helpers:

- Fleet: `list_orgs`, `client_info`, `list_clients`, `hunt_across_fleet`, `get_hunt_results_tool`, `run_vql`.
- Linux: process, group, mount, network, users, crontab, services, SSH keys/logins, shell history, last login, ARP cache, journal search, file finder, and YARA process scanning.
- macOS: process, users, network, LaunchAgents/Daemons, login items, shell history, browser history, quarantine events, TCC database, file finder, and artifact discovery.
- Windows: process, network, scheduled tasks, services, RecentDocs, Shellbags, USB/mount evidence, execution traces, MFT, USN, SRUM, EVTX, PowerShell, autoruns, WMI persistence, RDP, DNS cache, Recycle Bin, browser history, memory/malfind/mutant checks, shadow copies, timestomp checks, and file/YARA hunting with optional hash calculation.
- Generic response/collection: `collect_artifact`, `get_collection_results`, `collect_forensic_triage`, `collect_file`, `quarantine_host`, `unquarantine_host`, and `kill_process`.

Thanks to [@snoe-findley](https://github.com/snoe-findley) for sharing a fork
that expanded available tools and some of the newer cross-platform additions.

![image](https://github.com/user-attachments/assets/3e810f03-ca74-4757-b5dc-89d4e8f8aef6)


### 6. Caveats

Due to the nature of DFIR, results depend on amount of data returned, model use and context window.

I have included a function to find artifacts and dynamically create collections but had mixed results.
I have been pleasantly surprised with some results and disappointed when running other collections that cause lots of rows.

Check licencing - Anthropic's DPA is only tied to their Commercial Terms, which means that for 
client/production endpoint data you would need commercial licencing to leverage this MCP. Other 
MCP clients work just fine.

Please let me know how you go and feel free to add PR!


`can you give me all network connections on MACHINENAME and look for suspicious processes?`
<img alt="image" src="https://github.com/user-attachments/assets/cc19ccde-f8fa-40d5-8b4d-82215777dc6b" />
<img alt="image" src="https://github.com/user-attachments/assets/734ce6d0-6c66-49cf-a0f7-8236f7435be3" />
<img alt="image" src="https://github.com/user-attachments/assets/b6593321-1089-4f00-8011-5ef08cf80d88" />

`can you tell me which artifacts target the USN journal`
<img alt="image" src="https://github.com/user-attachments/assets/b9f93b1c-4a08-437d-b25a-ff82bdd2ab8c" />
