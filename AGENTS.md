# AGENTS.md

## Purpose

This repo is a proof-of-concept MCP bridge for Velociraptor DFIR workflows.
Future work should bias toward small, verified improvements that make the bridge
portable, testable, and safe to run under stdio-based MCP clients.

## Repo Map

- `mcp_velociraptor_bridge.py`: FastMCP server and tool registry.
- `velociraptor_api.py`: gRPC setup plus VQL execution helpers.
- `agent_poc/velociraptor_mcp_runtime.py`: shared MCP + Ollama runtime used by the agent.
- `agent_poc/mcp_agent.py`: higher-level autonomous workflow example.
- `agent_poc/README.md`: agent-specific usage and integration notes.
- `test_api.py`: manual smoke script, not an automated test suite.
- `README.md`: top-level bridge and setup documentation.

## Ground Rules

- Inspect `git status --short` before editing. The worktree may already be dirty.
- Do not add more hard-coded user-specific paths, especially config paths.
- Treat stdout as protocol-sensitive when working on MCP server code. Use stderr or
  structured logging for diagnostics.
- Keep changes small. Prefer one behavioral fix or one structural improvement per
  iteration.
- When tool names, parameters, or startup behavior change, update both READMEs in
  the same iteration.

## Local Commands

Use the repo virtualenv directly because `python` is not guaranteed to exist on
`PATH` in this environment.

- Syntax check:
  `.venv/bin/python -m py_compile mcp_velociraptor_bridge.py velociraptor_api.py agent_poc/velociraptor_mcp_runtime.py agent_poc/mcp_agent.py test_api.py`
- Manual API smoke script:
  `.venv/bin/python test_api.py`
- Start the MCP bridge directly:
  `.venv/bin/python mcp_velociraptor_bridge.py`
- Run the agent:
  `.venv/bin/python -m agent_poc.mcp_agent RE-DEV`


## Iteration Template

For each change:

1. Pick one small target from the preferred improvement order.
2. Read the touched files completely before editing.
3. Make the smallest patch that solves the problem.
4. Run syntax checks or targeted tests.
5. Update docs if the user-facing workflow changed.
6. Leave a short note in the final response covering:
   what changed, how it was verified, and what should come next.

## Definition Of Done For Future PRs

- No new hard-coded local paths or secrets.
- No user-specific filesystem paths in tracked files intended for GitHub.
- Server code does not write arbitrary data to stdout.
- A changed behavior is covered by at least one verification step.
- Docs match the actual startup and configuration path.
- The next improvement step remains obvious and bounded.
