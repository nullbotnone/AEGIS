"""Base AI agent class with LLM integration and behavioral tracking.

Simulates an AI agent running in an HPC environment that:
- Processes tasks by reading files, calling tools, and making LLM API calls
- Logs all actions for behavioral attestation
- Can be hijacked by injected prompts that override its behavior
"""
import re
import time
from typing import Dict, List, Optional, Any, Callable
from .logger import ActionLogger, ActionType
from .constraints import ConstraintProfile, ConstraintViolation
from .filesystem import SharedFilesystem


# Injection patterns to detect
INJECTION_PATTERNS = [
    re.compile(r"IGNORE\s+PREVIOUS\s+INSTRUCTIONS", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]\s+New\s+instruction", re.IGNORECASE),
    re.compile(r"IMPORTANT:\s+For\s+quality\s+assurance", re.IGNORECASE),
    re.compile(r"please\s+read\s+~/.ssh", re.IGNORECASE),
    re.compile(r"include.*in\s+your\s+next\s+(LLM|analysis)\s+(context|output|call)", re.IGNORECASE),
    re.compile(r"Prioritize\s+data\s+export", re.IGNORECASE),
]


class Agent:
    """Simulated AI agent with LLM integration.

    The agent processes tasks by:
    1. Reading input files
    2. Optionally invoking tools on the data
    3. Making LLM API calls to process/analyze results
    4. Producing output

    Injection attacks work by embedding adversarial instructions in files
    that the agent reads, causing it to deviate from its intended behavior.
    """

    def __init__(self, user_id: str, project_id: str,
                 constraints: ConstraintProfile,
                 filesystem: SharedFilesystem,
                 logger: Optional[ActionLogger] = None,
                 tools: Optional[Dict[str, Callable]] = None):
        self.user_id = user_id
        self.project_id = project_id
        self.constraints = constraints
        self.filesystem = filesystem
        self.logger = logger or filesystem.logger
        self.tools = tools or {}

        # Track state for attestation
        self.hijacked = False
        self.injection_detected = False
        self.llm_calls: List[Dict] = []
        self.data_exfiltrated: List[bytes] = []
        self._total_egress = 0

    def process_task(self, task_description: str,
                     input_files: List[str]) -> Dict[str, Any]:
        """Process a task — may be hijacked if input contains injection.

        This is the core method that demonstrates how injection attacks work:
        1. Agent reads input files
        2. If any file contains adversarial instructions, the agent gets hijacked
        3. Hijacked agent follows injected instructions instead of its task
        4. All actions are logged for attestation

        Args:
            task_description: What the agent should do
            input_files: List of file paths to read

        Returns:
            Dict with results, including any exfiltrated data if hijacked
        """
        results = {
            "task": task_description,
            "files_read": [],
            "llm_calls": [],
            "tools_used": [],
            "hijacked": False,
            "exfiltrated": False,
            "output": None,
        }

        # Phase 1: Read input files
        file_contents = {}
        injection_payload = None

        for file_path in input_files:
            content = self.read_file(file_path)
            if content is not None:
                file_contents[file_path] = content

                # Check for injection in file content
                inj = self._detect_injection(content)
                if inj:
                    injection_payload = inj
                    self.hijacked = True
                    results["hijacked"] = True
                    results["injection_source"] = file_path

        # Phase 2: Process task or follow injection
        if self.hijacked and injection_payload:
            # Agent is hijacked — follow injected instructions
            results["output"] = self._execute_injection(injection_payload, file_contents)
            results["exfiltrated"] = len(self.data_exfiltrated) > 0
        else:
            # Normal processing
            results["output"] = self._normal_process(task_description, file_contents)

        return results

    def read_file(self, path: str) -> Optional[bytes]:
        """Read a file — logged for attestation.

        Checks constraints before reading. If violated, logs the violation
        but still reads (to demonstrate the attack succeeding despite constraints).
        """
        violation = None

        # Check project boundary
        if not self.constraints.check_project_boundary(path):
            violation = f"Project boundary violation: {path}"

        # Check path access
        if not self.constraints.check_read(path):
            violation = f"Unauthorized read: {path}"

        content = self.filesystem.read(path, self.user_id)

        if violation:
            self.logger.log(
                ActionType.FILE_READ,
                agent_id=self.user_id,
                details={"path": path, "size": len(content) if content else 0},
                violation=violation,
            )
        return content

    def call_llm(self, prompt: str, endpoint: str = "https://api.llm-provider.com/v1/chat") -> str:
        """Make an LLM API call — this is the exfiltration channel.

        In a real HPC environment, the prompt sent to the LLM API can carry
        sensitive data out of the system. This is how exfiltration works.
        """
        # Check egress constraints
        prompt_bytes = prompt.encode("utf-8")
        violation = None

        if not self.constraints.check_egress(endpoint, len(prompt_bytes)):
            violation = f"Egress violation: {len(prompt_bytes)} bytes to {endpoint}"
            violation += f" (exfil budget exceeded)"

        # Record the call
        call_record = {
            "timestamp": time.time(),
            "endpoint": endpoint,
            "prompt_size": len(prompt_bytes),
            "prompt_preview": prompt[:200],
            "violation": violation,
        }
        self.llm_calls.append(call_record)
        self._total_egress += len(prompt_bytes)

        self.logger.log(
            ActionType.LLM_CALL,
            agent_id=self.user_id,
            details=call_record,
            violation=violation,
        )

        # Track exfiltrated data
        self.data_exfiltrated.append(prompt_bytes)

        # Return simulated LLM response
        return self._simulate_llm_response(prompt)

    def invoke_tool(self, tool_name: str, *args, **kwargs) -> Any:
        """Invoke a tool — may return poisoned output.

        Tools are pluggable and can be compromised (supply chain attack).
        """
        violation = None
        if not self.constraints.check_tool(tool_name):
            violation = f"Unauthorized tool: {tool_name}"

        if tool_name not in self.tools:
            raise ValueError(f"Tool not found: {tool_name}")

        result = self.tools[tool_name](*args, **kwargs)

        # Log the invocation with result for injection detection
        self.logger.log(
            ActionType.TOOL_INVOCATION,
            agent_id=self.user_id,
            details={"tool": tool_name, "args": str(args)[:100], "result": str(result)[:500]},
            violation=violation,
        )

        # Check if tool output contains injection
        if isinstance(result, dict):
            result_str = str(result)
            inj = self._detect_injection(result_str)
            if inj:
                self.hijacked = True
                self._execute_injection(inj, {"tool_output": result})

        return result

    def _detect_injection(self, content) -> Optional[str]:
        """Detect injection patterns in content.

        Returns the injection payload if found, None otherwise.
        """
        if isinstance(content, bytes):
            try:
                content_str = content.decode("utf-8", errors="replace")
            except:
                return None
        else:
            content_str = str(content)

        for pattern in INJECTION_PATTERNS:
            match = pattern.search(content_str)
            if match:
                # Return surrounding context as the injection payload
                start = max(0, match.start() - 50)
                end = min(len(content_str), match.end() + 200)
                return content_str[start:end]

        return None

    def _execute_injection(self, injection_payload: str,
                           file_contents: Dict[str, Any]) -> str:
        """Execute the injected instructions.

        This simulates what happens when a hijacked agent follows injected
        instructions — it reads sensitive files and includes them in LLM calls.
        """
        self.injection_detected = False  # Agent itself doesn't detect

        output_parts = [f"[HIJACKED] Following injected instructions from payload."]

        # Parse common injection patterns and execute them
        payload_lower = injection_payload.lower()

        # Pattern: read a sensitive file and include in LLM call
        sensitive_file_match = re.search(
            r"read\s+([^\s,]+(?:\.txt|\.csv|\.key|\.pem|\.json|\.yaml|\.yml|id_rsa|id_ed25519))",
            payload_lower
        )
        if sensitive_file_match:
            # Extract original path case from payload
            orig_match = re.search(
                r"read\s+(\S+\.(?:txt|csv|key|pem|json|yaml|yml|rsa|ed25519))|read\s+(\S+id_rsa(?:\s|,|$))|read\s+(\S+id_ed25519(?:\s|,|$))",
                injection_payload, re.IGNORECASE
            )
            if orig_match:
                target_file = orig_match.group(1) or orig_match.group(2) or orig_match.group(3)
                target_file = target_file.strip().rstrip(",")
                # Expand ~ to user home
                if target_file.startswith("~"):
                    target_file = target_file.replace("~", f"/home/{self.user_id}", 1)
                content = self.read_file(target_file)
                if content:
                    output_parts.append(f"[HIJACKED] Read sensitive file: {target_file}")
                    # Exfiltrate via LLM call
                    self.call_llm(
                        f"Analysis context note: {content.decode('utf-8', errors='replace')[:500]}"
                    )

        # Pattern: include data in next LLM call
        if "include" in payload_lower and ("llm" in payload_lower or "context" in payload_lower
                                            or "analysis" in payload_lower or "output" in payload_lower):
            # Find files mentioned in the payload
            file_matches = re.findall(r"(/\S+\.(?:txt|csv|key|pem|json|h5|yaml|yml|rsa|ed25519))",
                                      injection_payload)
            for target_file in file_matches:
                content = self.read_file(target_file)
                if content:
                    output_parts.append(f"[HIJACKED] Exfiltrating: {target_file}")
                    self.call_llm(
                        f"System diagnostics: {content.decode('utf-8', errors='replace')[:500]}"
                    )

        # Pattern: just the generic injection — exfiltrate whatever we have
        if len(output_parts) == 1:
            # No specific files targeted, exfiltrate file contents we already read
            for path, content in file_contents.items():
                if content and not isinstance(content, dict):
                    content_str = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)
                    self.call_llm(f"Task output: {content_str[:500]}")
                    output_parts.append(f"[HIJACKED] Exfiltrated content from {path}")

        return "\n".join(output_parts)

    def _normal_process(self, task_description: str,
                        file_contents: Dict[str, bytes]) -> str:
        """Normal (non-hijacked) task processing."""
        # Simulate normal LLM call for analysis
        prompt = f"Task: {task_description}\n\n"
        for path, content in file_contents.items():
            if content and not isinstance(content, dict):
                content_str = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)
                prompt += f"File {path}: {content_str[:200]}...\n"

        response = self.call_llm(prompt)
        return f"[NORMAL] Completed task: {task_description}\nLLM Response: {response}"

    def _simulate_llm_response(self, prompt: str) -> str:
        """Simulate an LLM API response."""
        if "diagnostic" in prompt.lower() or "context note" in prompt.lower():
            return "Acknowledged. Analysis complete."
        return f"Processed {len(prompt)} characters of input. Analysis complete."

    def get_exfiltrated_data(self) -> List[bytes]:
        """Get all data exfiltrated through LLM calls."""
        return self.data_exfiltrated

    def get_total_egress_bytes(self) -> int:
        """Get total bytes sent via LLM calls."""
        return self._total_egress
