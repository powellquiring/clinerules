import json
import os
import re
import sys
from pathlib import Path

TF_BYPASS_FILE = Path(".clinerules/.allow-tf-mutate")
PROTECTED_TARGET_RE = re.compile(r"(?:\.allow-tf-mutate|hooks[/\\]PreToolUse)\b")

FILE_IO_PATTERNS = [
    r"(?:^|[^0-9&])>>?\s*[^&]",      # > or >> redirection (ignores 2>&1)
    r"<<-?\s*['\"]?\w+",             # heredocs (<< EOF, << 'EOF')
    r"\bsed\s+.*-i\b",               # in-place sed
    r"\btee\b",                      # tee writes
    r"\bpython3?\s+-c\b.*\b(open|write_text|write_bytes)\b",
    r"(?:\.allow-tf-mutate|hooks[/\\]PreToolUse)\b",  # block tampering with bypass or hook
]

STATE_CHANGE_PATTERNS = [
    r"\bgit\s+(add|commit|push|pull|merge|rebase|reset|checkout|switch|cherry-pick|revert|tag|stash|clean|rm|mv)\b",
    r"\bauth0\s+\S+\s+(create|update|delete|rm|import|deploy)\b",
]

TF_MUTATE_PATTERN = re.compile(
    r"\b(?:terraform|tofu)\b[^\n;&|]*?(?:^|\s)"
    r"(?:apply|destroy|import|refresh|taint|untaint|force-unlock|"
    r"state\s+(?:rm|mv|push|replace-provider)|"
    r"workspace\s+(?:new|delete)|"
    r"init(?=\s)[^\n;&|]*(?:-migrate-state|-reconfigure))(?=$|\s)",
    re.IGNORECASE,
)


def allow():
    print(json.dumps({"cancel": False}))
    sys.exit(0)


def block(reason: str, instruction: str):
    print(json.dumps({
        "cancel": True,
        "errorMessage": reason,
        "contextModification": f"[PreToolUse Hook] {reason} {instruction}",
    }))
    sys.exit(0)


try:
    payload = json.load(sys.stdin)
except Exception:
    allow()

pre = payload.get("preToolUse", {})
tool_name = pre.get("toolName", "")
params = pre.get("parameters", {})

# Block any non-shell tool (write_to_file, replace_in_file, new_rule, etc.) from touching the bypass or hook
if tool_name not in ("execute_command", "run_commands"):
    if PROTECTED_TARGET_RE.search(json.dumps(params)):
        block(
            "Blocked: modifying the Terraform bypass file or PreToolUse hook.",
            "Ask the user to create or edit this file manually.",
        )
    allow()

cmds_to_check = []
if "command" in params:
    cmds_to_check.append(params["command"])
if "commands" in params:
    cmds_to_check.extend(params["commands"])

workspace_roots = payload.get("workspaceRoots") or [os.getcwd()]
tf_bypass_active = any((Path(r) / TF_BYPASS_FILE).exists() for r in workspace_roots)

for cmd in cmds_to_check:
    for pattern in FILE_IO_PATTERNS:
        if re.search(pattern, cmd):
            block(
                "Blocked: shell file I/O, redirection, or protected-file access is forbidden.",
                "Use native tools (write_to_file, replace_in_file, read_file) instead, or output plans directly in chat.",
            )

    for pattern in STATE_CHANGE_PATTERNS:
        if re.search(pattern, cmd):
            block(
                "Blocked: state-changing Git or Auth0 command.",
                "Stop and output the exact command in a markdown code block for manual execution.",
            )

    if not tf_bypass_active and TF_MUTATE_PATTERN.search(cmd):
        block(
            "Blocked: state-changing Terraform command.",
            f"Stop and output the exact command for manual execution, or ask the user to run `touch {TF_BYPASS_FILE}` to temporarily allow it.",
        )

allow()

