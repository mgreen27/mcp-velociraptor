# Velociraptor Agent POC

### Setup
```bash
.venv/bin/python -m pip install -r requirements.txt
ollama pull gemma4:e2b
```

### Usage
```bash
export VELOCIRAPTOR_API_CONFIG=/path/to/api_client.yaml
export OLLAMA_MODEL=gemma4:e2b
.venv/bin/python -m agent_poc.mcp_agent RE-DEV
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

### Analysis Types
- **triage**: Quick check (processes, network, client info)
- **process**: Deep process analysis
- **network**: Network connection analysis
- **persistence**: Check scheduled tasks, services, etc.
- **execution**: Evidence of execution artifacts
- **full**: Comprehensive investigation

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
  ├── WIN10-WS_triage_20240115_143022.json
  ├── DC01_full_20240115_150033.json
  └── ...
```

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

The bridge and smoke script both read `VELOCIRAPTOR_API_CONFIG`. Keep that file
local and out of version control.
The agent reads `OLLAMA_MODEL` and defaults to `gemma4:e2b`.
Each `analyze_endpoint()` run resets prior chat state so repeated or batch
analyses start from fresh host-specific context.
For multi-tenant deployments, set `VELOCIRAPTOR_ORG_ID` for the default org, or
pass `org_id` directly to MCP tools such as `client_info`, `windows_pslist`,
`collect_artifact`, and `get_collection_results`.

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
