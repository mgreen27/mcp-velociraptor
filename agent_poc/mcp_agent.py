"""
Headless Agent for Automated Velociraptor DFIR Analysis
"""
import argparse
import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .velociraptor_mcp_runtime import VelociraptorMCPClient
except ImportError:
    from velociraptor_mcp_runtime import VelociraptorMCPClient


class VelociraptorAgent:
    """
    Autonomous agent for forensic analysis workflows.
    Can be triggered via API, scheduled tasks, or alert integrations.
    """
    
    def __init__(self, model: Optional[str] = None, output_dir: Optional[str] = None):
        resolved_model = model or os.environ.get("OLLAMA_MODEL", "gemma4:e2b")
        self.client = VelociraptorMCPClient(model=resolved_model)
        self.output_dir = output_dir or str(Path(__file__).resolve().parent / "output")
        self.analysis_results = []
        
    async def initialize(self):
        """Initialize the agent and connect to MCP bridge"""
        await self.client.connect()
        print(f"✓ Agent initialized with {len(self.client.tools)} tools")
        
    async def shutdown(self):
        """Cleanup and disconnect"""
        await self.client.disconnect()
        
    async def analyze_endpoint(
        self,
        hostname: str,
        analysis_type: str = "triage"
    ) -> Dict:
        """
        Perform automated analysis on an endpoint.
        
        Args:
            hostname: Target hostname or client_id
            analysis_type: Type of analysis (triage, process, network, persistence, execution)
        
        Returns:
            Dictionary containing analysis results
        """
        print(f"\n🔍 Starting {analysis_type} analysis for: {hostname}")
        self.client.reset_conversation()
        
        analysis_workflows = {
            "triage": self._triage_workflow,
            "process": self._process_analysis_workflow,
            "network": self._network_analysis_workflow,
            "persistence": self._persistence_workflow,
            "execution": self._execution_workflow,
            "full": self._full_investigation_workflow
        }
        
        workflow = analysis_workflows.get(analysis_type, self._triage_workflow)
        results = await workflow(hostname)
        
        # Save results
        self._save_results(hostname, analysis_type, results)
        
        return results

    async def _resolve_client_info(self, hostname: str) -> Optional[Dict]:
        """Resolve hostname to client metadata deterministically via the MCP tool."""
        raw_result = await self.client.call_tool("client_info", {"hostname": hostname})
        try:
            parsed = json.loads(raw_result)
        except json.JSONDecodeError:
            parsed = None

        if parsed:
            return parsed

        raw_result = await self.client.call_tool(
            "client_info",
            {"hostname": hostname, "search_all_orgs": True},
        )
        try:
            parsed = json.loads(raw_result)
        except json.JSONDecodeError:
            parsed = None

        return parsed

    @staticmethod
    def _target_phrase(client_info: Dict) -> str:
        os_type = (client_info.get("OSType") or "unknown").lower()
        client_id = client_info["client_id"]
        org_id = client_info.get("OrgId")
        prefix = f"{os_type} " if os_type != "unknown" else ""
        if org_id:
            return f"{prefix}client {client_id} in org {org_id}"
        return f"{prefix}client {client_id}"

    @staticmethod
    def _platform_guidance(client_info: Dict) -> str:
        os_type = (client_info.get("OSType") or "").lower()
        if os_type == "windows":
            return "This endpoint is Windows. Use Windows-specific Velociraptor tools only."
        if os_type == "linux":
            return "This endpoint is Linux. Use Linux-specific Velociraptor tools only."
        return "Choose tools based on the resolved endpoint metadata."
    
    async def _triage_workflow(self, hostname: str) -> Dict:
        """Quick triage: client info + running processes + network connections"""
        results = {"workflow": "triage", "findings": []}

        client_info = await self._resolve_client_info(hostname)
        results["findings"].append({"step": "client_info", "result": client_info})
        if not client_info:
            results["error"] = "Could not determine client_id"
            return results

        client_id = client_info["client_id"]
        results["client_id"] = client_id
        if client_info.get("OrgId"):
            results["org_id"] = client_info["OrgId"]

        target = self._target_phrase(client_info)
        platform_guidance = self._platform_guidance(client_info)

        response = await self.client.chat(
            f"Analyze running processes on {target}. "
            f"{platform_guidance} "
            "Focus on unusual or suspicious processes, unsigned binaries, elevated "
            "tokens, odd parent-child relationships, temp-directory execution, and "
            "suspicious command lines."
        )
        results["findings"].append({"step": "processes", "result": response})

        response = await self.client.chat(
            f"Analyze network connections on {target}. "
            f"{platform_guidance} "
            "Highlight unusual external connections, suspicious ports, and processes "
            "with risky network activity."
        )
        results["findings"].append({"step": "network", "result": response})
        
        return results
    
    async def _process_analysis_workflow(self, hostname: str) -> Dict:
        """Deep process analysis"""
        results = {"workflow": "process_analysis", "findings": []}

        client_info = await self._resolve_client_info(hostname)
        results["findings"].append({"step": "client_info", "result": client_info})
        if not client_info:
            results["error"] = "Could not determine client_id"
            return results

        results["client_id"] = client_info["client_id"]
        if client_info.get("OrgId"):
            results["org_id"] = client_info["OrgId"]
        target = self._target_phrase(client_info)
        platform_guidance = self._platform_guidance(client_info)

        response = await self.client.chat(
            f"Analyze all running processes on {target}. "
            f"{platform_guidance} "
            "Look for unsigned binaries, elevated processes, unusual parent-child "
            "relationships, processes running from temp directories, suspicious "
            "command lines, and names masquerading as legitimate Windows processes."
        )
        results["findings"].append({"step": "process_analysis", "result": response})
        
        return results
    
    async def _network_analysis_workflow(self, hostname: str) -> Dict:
        """Network connection analysis"""
        results = {"workflow": "network_analysis", "findings": []}

        client_info = await self._resolve_client_info(hostname)
        results["findings"].append({"step": "client_info", "result": client_info})
        if not client_info:
            results["error"] = "Could not determine client_id"
            return results

        results["client_id"] = client_info["client_id"]
        if client_info.get("OrgId"):
            results["org_id"] = client_info["OrgId"]
        target = self._target_phrase(client_info)
        platform_guidance = self._platform_guidance(client_info)

        response = await self.client.chat(
            f"Analyze network connections on {target}. "
            f"{platform_guidance} "
            "Focus on external IPs, unusual ports, unsigned processes with network "
            "activity, unexpected listening sockets, and established connections to "
            "suspicious destinations."
        )
        results["findings"].append({"step": "network_analysis", "result": response})
        
        return results
    
    async def _persistence_workflow(self, hostname: str) -> Dict:
        """Persistence mechanism analysis"""
        results = {"workflow": "persistence", "findings": []}

        client_info = await self._resolve_client_info(hostname)
        results["findings"].append({"step": "client_info", "result": client_info})
        if not client_info:
            results["error"] = "Could not determine client_id"
            return results

        results["client_id"] = client_info["client_id"]
        if client_info.get("OrgId"):
            results["org_id"] = client_info["OrgId"]
        target = self._target_phrase(client_info)
        platform_guidance = self._platform_guidance(client_info)

        response = await self.client.chat(
            f"Check persistence mechanisms on {target}. "
            f"{platform_guidance} "
            "Review scheduled tasks, services, and startup items. Look for suspicious, "
            "recently added, unsigned, or user-writable persistence entries."
        )
        results["findings"].append({"step": "persistence_check", "result": response})
        
        return results
    
    async def _execution_workflow(self, hostname: str) -> Dict:
        """Evidence of execution analysis"""
        results = {"workflow": "execution", "findings": []}

        client_info = await self._resolve_client_info(hostname)
        results["findings"].append({"step": "client_info", "result": client_info})
        if not client_info:
            results["error"] = "Could not determine client_id"
            return results

        results["client_id"] = client_info["client_id"]
        if client_info.get("OrgId"):
            results["org_id"] = client_info["OrgId"]
        target = self._target_phrase(client_info)
        platform_guidance = self._platform_guidance(client_info)

        response = await self.client.chat(
            f"Analyze evidence of execution on {target}. "
            f"{platform_guidance} "
            "Use prefetch, shimcache, amcache, userassist, and related execution "
            "artifacts to look for suspicious executables or tools commonly used by attackers."
        )
        results["findings"].append({"step": "execution_artifacts", "result": response})
        
        return results
    
    async def _full_investigation_workflow(self, hostname: str) -> Dict:
        """Comprehensive investigation workflow"""
        results = {"workflow": "full_investigation", "findings": []}
        
        # Run all workflows
        for workflow_name, workflow_func in [
            ("triage", self._triage_workflow),
            ("persistence", self._persistence_workflow),
            ("execution", self._execution_workflow)
        ]:
            workflow_results = await workflow_func(hostname)
            results["findings"].extend(workflow_results.get("findings", []))
        
        # Final synthesis
        response = await self.client.chat(
            "Based on all the analysis above, provide a summary of key findings "
            "and any indicators of compromise or suspicious activity"
        )
        results["findings"].append({"step": "synthesis", "result": response})
        
        return results
    
    async def batch_analyze(
        self,
        hostnames: List[str],
        analysis_type: str = "triage"
    ) -> List[Dict]:
        """Analyze multiple endpoints"""
        results = []
        
        for hostname in hostnames:
            try:
                result = await self.analyze_endpoint(hostname, analysis_type)
                results.append(result)
            except Exception as e:
                results.append({
                    "hostname": hostname,
                    "error": str(e)
                })
        
        return results
    
    def _save_results(self, hostname: str, analysis_type: str, results: Dict):
        """Save analysis results to JSON file"""
        os.makedirs(self.output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/{hostname}_{analysis_type}_{timestamp}.json"
        
        with open(filename, "w") as f:
            json.dump({
                "hostname": hostname,
                "analysis_type": analysis_type,
                "timestamp": timestamp,
                "results": results
            }, f, indent=2)
        
        print(f"✓ Results saved to: {filename}")


def _format_value(value: Any) -> str:
    if value is None:
        return "None"
    if isinstance(value, str):
        return value.strip() or "(empty)"
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2)
    return str(value)


def format_results_text(results: Dict) -> str:
    """Render analysis results in a readable text format."""
    lines = [
        f"Workflow: {results.get('workflow', 'unknown')}",
    ]

    if results.get("client_id"):
        lines.append(f"Client ID: {results['client_id']}")
    if results.get("org_id"):
        lines.append(f"Org ID: {results['org_id']}")
    if results.get("error"):
        lines.append(f"Error: {results['error']}")

    findings = results.get("findings", [])
    if findings:
        lines.append("")
        lines.append("Findings:")
        for finding in findings:
            step = finding.get("step", "unknown")
            result = _format_value(finding.get("result"))
            lines.append(f"[{step}]")
            lines.append(result)
            lines.append("")

    return "\n".join(lines).rstrip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Velociraptor agent analysis for a target hostname"
    )
    parser.add_argument(
        "hostname",
        nargs="?",
        default="RE-DEV",
        help="Target hostname to analyze (default: RE-DEV)"
    )
    parser.add_argument(
        "-t",
        "--analysis-type",
        default="triage",
        choices=["triage", "process", "network", "persistence", "execution", "full"],
        help="Analysis workflow to run"
    )
    parser.add_argument(
        "--output-type",
        default="json",
        choices=["json", "text"],
        help="Print machine-readable JSON or a readable text summary"
    )
    return parser.parse_args()


async def main():
    """CLI entry point for the agent"""
    args = parse_args()
    agent = VelociraptorAgent()
    
    try:
        await agent.initialize()

        results = await agent.analyze_endpoint(
            hostname=args.hostname,
            analysis_type=args.analysis_type
        )
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)
        if args.output_type == "text":
            print(format_results_text(results))
        else:
            print(json.dumps(results, indent=2))
    finally:
        await agent.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
