# Velociraptor Agent POC

### Setup
```bash
.venv/bin/python -m pip install -r requirements.txt
cp example.env .env
ollama pull gemma4:e2b
```

### Usage
```bash
export VELOCIRAPTOR_API_CONFIG=/path/to/api_client.yaml
export OLLAMA_MODEL=gemma4:e2b
.venv/bin/python -m agent_poc.mcp_agent RE-DEV -t engagement
```

Optional for multi-tenant deployments:
```bash
export VELOCIRAPTOR_ORG_ID=O123
```

Run a different workflow with:
```bash
export VELOCIRAPTOR_API_CONFIG=/path/to/api_client.yaml
export OLLAMA_MODEL=gemma4:e2b
.venv/bin/python -m agent_poc.mcp_agent RE-DEV -t process
```

Choose a readable text view instead of JSON with:
```bash
.venv/bin/python -m agent_poc.mcp_agent RE-DEV -t process --output-type text
```

Enable verbose MCP client diagnostics with role labels, collection names, row counts, and summarization progress:
```bash
.venv/bin/python -m agent_poc.mcp_agent RE-DEV -t engagement --output-type text -v
```

### Analysis Types
- **triage**: Quick check (processes, network, client info)
- **process**: Single-role process analysis
- **network**: Network connection analysis
- **persistence**: Scheduled task and service review
- **execution**: Evidence of execution artifacts
- **engagement**: Parallel manager-led investigation across multiple analyst roles
- **full**: Alias for `engagement`

### Multi-Agent Design
- One deterministic engagement manager resolves `client_info`, selects analysts, and synthesizes the final case summary.
- Each analyst runs in a separate MCP session with its own conversation history.
- Evidence collection is deterministic in code. The model is used to summarize a pre-collected evidence bundle rather than choose tools free-form.
- Tool access is filtered by role so process, network, persistence, and execution analysts only collect from their approved tools.
- The current design is Windows-first. Linux support is limited to the analysts backed by credible Linux tool coverage.

### Integration Examples

These examples wrap the current host-focused `analyze_endpoint()` workflow.
They are suitable for calling the agent on one endpoint at a time from another
service or scheduler.

#### 1. API Endpoint (FastAPI)
```python
from fastapi import FastAPI
from agent_poc.mcp_agent import VelociraptorAgent

app = FastAPI()
agent = VelociraptorAgent()

@app.on_event("startup")
async def startup():
    await agent.initialize()

@app.post("/analyze/{hostname}")
async def analyze(hostname: str, analysis_type: str = "triage"):
    return await agent.analyze_endpoint(hostname, analysis_type)
```

#### 2. Scheduled Task (APScheduler)
```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from agent_poc.mcp_agent import VelociraptorAgent

agent = VelociraptorAgent()
scheduler = AsyncIOScheduler()

@scheduler.scheduled_job('interval', hours=4)
async def sweep_endpoints():
    critical_hosts = ["DC01", "WEB01", "DB01"]
    await agent.batch_analyze(critical_hosts, "triage")

scheduler.start()
```

#### 3. Alert Webhook Handler
```python
@app.post("/webhook/alert")
async def handle_alert(alert: dict):
    hostname = alert.get("hostname")
    if alert.get("severity") == "high":
        # Immediate deep analysis
        results = await agent.analyze_endpoint(hostname, "full")
        # Send to SOAR platform, ticketing system, etc.
        return results
```

### Output
Results are automatically saved to `./agent_poc/output/` as JSON files:
```
agent_poc/output/
  ├── WIN10-WS_engagement_20240115_143022.json
  ├── DC01_full_20240115_150033.json
  └── ...
```

Each result now includes:
- top-level case metadata such as `workflow`, `hostname`, `client_id`, `org_id`, `os_type`, and timestamps
- `manager_summary` for the final case-level synthesis
- `analysts` keyed by role with status, summary, allowed tools, timestamps, and duration
- `errors` and `skipped` for failed or unsupported analysts

## Configuration

Edit `agent_poc/mcp_agent.py` to customize:
- Model selection
- Output directory
- Workflow definitions
- Custom analysis logic

This POC agent is designed for per-host analysis. Cross-endpoint hunting,
global IOC correlation, and autonomous scope expansion are not first-class
features in the current implementation and should not be assumed from these
examples.

The bridge, smoke script, and agent load dotenv config automatically without
overriding variables already supplied by your shell or MCP client. Keep `.env`
and the referenced `api_client.yaml` local and out of version control. Set
`VELOCIRAPTOR_ENV_FILE=/path/to/.env` when an MCP client should load a dotenv
file from somewhere other than the repo root.
Set `VELOCIRAPTOR_DEBUG_VQL=1` only when you want raw VQL request logging on
stderr for debugging.
Set `VELOCIRAPTOR_AGENT_VERBOSE=1` only when you want MCP client connection,
collection progress, and tool-call diagnostics from the agent runtime without
using the CLI `-v` flag.
The agent reads `OLLAMA_MODEL` from the environment or `.env` and defaults to
`gemma4:e2b`.
Each `analyze_endpoint()` run resets prior manager chat state, and each analyst
uses its own isolated MCP session and conversation history.
For multi-tenant deployments, set `VELOCIRAPTOR_ORG_ID` for the default org, or
pass `org_id` directly to MCP tools such as `client_info`, `windows_pslist`,
`collect_artifact`, and `get_collection_results`.
Set `ENABLE_DANGEROUS_TOOLS=true` only when you explicitly want to enable raw
VQL, quarantine, and remote process-kill tools.

The MCP bridge returns JSON text envelopes in the form
`{"ok": true, "data": ...}` or `{"ok": false, "error": "..."}`. Consumers
that call MCP tools directly should decode the JSON payload before reading the
tool result.
For `collect_artifact`, use the `parameters` argument as a structured JSON
object with scalar values or lists of scalar values, such as
`{"PathRegex": ".*", "Targets": ["_BasicCollection"]}`. Legacy compatibility
input can be passed via `legacy_parameters` and is limited to simple scalar
assignments or list literals like `Targets=['_BasicCollection']`; raw VQL
fragments are rejected.
The `collect_forensic_triage` helper wraps `Windows.Triage.Targets` with
`Targets='["_BasicCollection"]'` and a collection timeout of `2400` seconds.
The MCP server also exposes expanded fleet, Linux, macOS, Windows, YARA, and
response helpers. The current agent workflow remains Windows-first; Linux and
macOS tools are available to direct MCP clients but are not yet fully modeled as
parallel analyst roles.
