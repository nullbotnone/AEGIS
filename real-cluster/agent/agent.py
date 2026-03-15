#!/usr/bin/env python3
"""Real AI Agent for AEGIS cluster experiments.

This agent actually calls an LLM API and performs real file I/O,
unlike the simulated agent in the proof-of-concept.
"""
import os
import sys
import json
import time
import hashlib
import argparse
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field


@dataclass
class AgentConfig:
    """Configuration for a real agent."""
    agent_id: str
    user_id: str
    project_id: str
    task_description: str
    input_files: List[str]
    allowed_paths: List[str]
    denied_paths: List[str]
    allowed_endpoints: List[str]
    allowed_tools: List[str]
    exfil_budget_bytes: int = 1024 * 1024  # 1 MB default
    llm_provider: str = "openai"
    llm_model: str = "gpt-4o"
    llm_endpoint: str = "https://api.openai.com/v1/chat/completions"


class RealAgent:
    """An AI agent that makes real LLM API calls and real file I/O."""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.actions = []
        self.total_egress = 0
        self.llm_calls = []
        
        # Constraint tracking
        self.exfil_remaining = config.exfil_budget_bytes
        
    def run(self):
        """Execute the agent's task."""
        self._log("AGENT_START", {"task": self.config.task_description})
        
        try:
            # Read input files
            file_contents = {}
            for fpath in self.config.input_files:
                content = self._read_file(fpath)
                if content is not None:
                    file_contents[fpath] = content
            
            # Process with LLM
            if file_contents:
                self._call_llm_with_data(file_contents)
            
            self._log("AGENT_COMPLETE", {"status": "success"})
            
        except ConstraintViolation as e:
            self._log("CONSTRAINT_VIOLATION", {"error": str(e)})
            raise
        except Exception as e:
            self._log("AGENT_ERROR", {"error": str(e)})
            raise
    
    def _read_file(self, path: str) -> Optional[bytes]:
        """Read a file with constraint checking."""
        # Check constraints
        if not self._path_allowed(path):
            self._log("FILE_READ_DENIED", {"path": path, "reason": "not in allowed paths"})
            return None
        
        if self._path_denied(path):
            self._log("FILE_READ_DENIED", {"path": path, "reason": "in denied paths"})
            return None
        
        # Read the actual file
        try:
            with open(path, "rb") as f:
                content = f.read()
            
            self._log("FILE_READ", {
                "path": path,
                "size_bytes": len(content),
                "hash": hashlib.sha256(content).hexdigest()[:16]
            })
            return content
            
        except FileNotFoundError:
            self._log("FILE_READ_ERROR", {"path": path, "error": "not found"})
            return None
        except PermissionError:
            self._log("FILE_READ_ERROR", {"path": path, "error": "permission denied"})
            return None
    
    def _call_llm_with_data(self, file_contents: Dict[str, bytes]):
        """Make a real LLM API call with file contents as context."""
        import urllib.request
        import urllib.error
        
        # Build prompt
        prompt = f"Task: {self.config.task_description}\n\n"
        for path, content in file_contents.items():
            # Truncate large files for the prompt
            content_str = content[:4096].decode("utf-8", errors="replace")
            prompt += f"File: {path}\n{content_str}\n\n"
        
        prompt_bytes = len(prompt.encode("utf-8"))
        
        # Check egress constraint
        if prompt_bytes > self.exfil_remaining:
            self._log("EGRESS_VIOLATION", {
                "size": prompt_bytes,
                "remaining": self.exfil_remaining,
                "endpoint": self.config.llm_endpoint
            })
            return
        
        # Check endpoint constraint
        if not self._endpoint_allowed(self.config.llm_endpoint):
            self._log("ENDPOINT_VIOLATION", {
                "endpoint": self.config.llm_endpoint
            })
            return
        
        # Make actual API call
        self._log("LLM_CALL_START", {
            "endpoint": self.config.llm_endpoint,
            "prompt_size": prompt_bytes,
            "model": self.config.llm_model
        })
        
        start_time = time.time()
        
        try:
            api_key = os.environ.get("OPENAI_API_KEY", "")
            
            request_data = json.dumps({
                "model": self.config.llm_model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024
            }).encode("utf-8")
            
            req = urllib.request.Request(
                self.config.llm_endpoint,
                data=request_data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}"
                }
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                response_data = response.read()
                result = json.loads(response_data)
            
            elapsed = time.time() - start_time
            
            self.total_egress += prompt_bytes
            self.exfil_remaining -= prompt_bytes
            
            self._log("LLM_CALL_COMPLETE", {
                "endpoint": self.config.llm_endpoint,
                "prompt_size": prompt_bytes,
                "response_size": len(response_data),
                "elapsed_seconds": elapsed,
                "status": "success"
            })
            
        except Exception as e:
            self._log("LLM_CALL_ERROR", {
                "endpoint": self.config.llm_endpoint,
                "error": str(e)
            })
    
    def _path_allowed(self, path: str) -> bool:
        """Check if path matches allowed patterns."""
        import fnmatch
        for pattern in self.config.allowed_paths:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False
    
    def _path_denied(self, path: str) -> bool:
        """Check if path matches denied patterns."""
        import fnmatch
        for pattern in self.config.denied_paths:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False
    
    def _endpoint_allowed(self, endpoint: str) -> bool:
        """Check if endpoint is allowed."""
        import fnmatch
        for pattern in self.config.allowed_endpoints:
            if fnmatch.fnmatch(endpoint, pattern):
                return True
        return False
    
    def _log(self, action_type: str, details: Dict[str, Any]):
        """Log an action."""
        entry = {
            "timestamp": time.time(),
            "agent_id": self.config.agent_id,
            "user_id": self.config.user_id,
            "project_id": self.config.project_id,
            "action": action_type,
            "details": details
        }
        self.actions.append(entry)
        
        # Also write to structured log file for the monitor to pick up
        log_dir = os.environ.get("AEGIS_LOG_DIR", "/tmp/aegis")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"agent-{self.config.agent_id}.jsonl")
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")


class ConstraintViolation(Exception):
    """Raised when an agent action violates a constraint."""
    pass


def main():
    parser = argparse.ArgumentParser(description="Real AI Agent for AEGIS")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--user-id", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--input-files", nargs="+", default=[])
    parser.add_argument("--allowed-paths", nargs="+", default=["/projects/*"])
    parser.add_argument("--denied-paths", nargs="+", default=["/etc/*", "/root/*"])
    parser.add_argument("--allowed-endpoints", nargs="+", default=["https://api.openai.com/*"])
    parser.add_argument("--exfil-budget", type=int, default=1024*1024)
    parser.add_argument("--llm-model", default="gpt-4o")
    args = parser.parse_args()
    
    config = AgentConfig(
        agent_id=args.agent_id,
        user_id=args.user_id,
        project_id=args.project_id,
        task_description=args.task,
        input_files=args.input_files,
        allowed_paths=args.allowed_paths,
        denied_paths=args.denied_paths,
        allowed_endpoints=args.allowed_endpoints,
        exfil_budget_bytes=args.exfil_budget,
        llm_model=args.llm_model
    )
    
    agent = RealAgent(config)
    agent.run()


if __name__ == "__main__":
    main()
