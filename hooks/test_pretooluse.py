import json
import subprocess

import pytest


def run_hook(payload):
    result = subprocess.run(
        ["python", "PreToolUse.py"],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
    )
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except json.JSONDecodeError:
        print(f"Failed to parse JSON. STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        raise


def create_payload(command, workspace_roots=None):
    payload = {
        "preToolUse": {"toolName": "run_commands", "parameters": {"command": command}}
    }
    if workspace_roots:
        payload["workspaceRoots"] = workspace_roots
    return payload


@pytest.mark.parametrize(
    "command",
    [
        "git add .",
        "git commit -m 'test'",
        "git push origin main",
        "git pull",
        "git merge branch",
        "git rebase main",
        "git reset --hard",
        "git checkout -b new",
        "git switch branch",
        "git rm file",
        "git mv a b",
        "git cherry-pick hash",
        "git revert hash",
        "git tag v1",
        "git stash",
        "git clean -fd",
    ],
)
def test_git_mutating_commands_blocked(command):
    payload = create_payload(command)
    result = run_hook(payload)
    assert result["cancel"] is True
    assert "Blocked: state-changing Git" in result.get("errorMessage", "")


@pytest.mark.parametrize(
    "command",
    [
        "git status",
        "git log",
        "git diff",
        "git branch",
        "git show",
        "git grep search",
    ],
)
def test_git_safe_commands_allowed(command):
    payload = create_payload(command)
    result = run_hook(payload)
    assert result["cancel"] is False


@pytest.mark.parametrize(
    "command",
    [
        "terraform apply",
        "tofu destroy -auto-approve",
        "terraform import aws_s3_bucket.bucket bucket-name",
        "terraform taint resource",
        "terraform untaint resource",
        "terraform force-unlock id",
        "terraform state rm resource",
        "terraform workspace new dev",
        "terraform workspace delete dev",
        "terraform init -migrate-state",
        "terraform init -reconfigure",
    ],
)
def test_terraform_mutating_commands_blocked(command):
    payload = create_payload(command)
    result = run_hook(payload)
    assert result["cancel"] is True
    assert "Blocked: state-changing Terraform" in result.get("errorMessage", "")


@pytest.mark.parametrize(
    "command",
    [
        "terraform plan",
        "terraform show",
        "terraform init",
        "tofu state list",
        "terraform workspace show",
        "terraform validate",
        "terraform output",
    ],
)
def test_terraform_safe_commands_allowed(command):
    payload = create_payload(command)
    result = run_hook(payload)
    assert result["cancel"] is False


def test_terraform_bypass_allowed(tmp_path):
    # Create the bypass file in a mock workspace
    clinerules_dir = tmp_path / ".clinerules"
    clinerules_dir.mkdir()
    bypass_file = clinerules_dir / ".allow-tf-mutate"
    bypass_file.touch()

    payload = create_payload("terraform apply", workspace_roots=[str(tmp_path)])
    result = run_hook(payload)

    # Because bypass is active, it should not be blocked
    assert result["cancel"] is False


@pytest.mark.parametrize(
    "command",
    [
        "cat << EOF > file.txt\nhello\nEOF",
        "cat <<- 'EOF'\ntest\nEOF",
        "echo hello >> file.txt",
        "ls > out.txt",
        "sed -i 's/a/b/g' file.txt",
        "echo test | tee file.txt",
        "python -c \"Path('test').write_text('abc')\"",
    ],
)
def test_file_io_blocked(command):
    payload = create_payload(command)
    result = run_hook(payload)
    assert result["cancel"] is True
    assert "Blocked: shell file I/O" in result.get("errorMessage", "")


@pytest.mark.parametrize(
    "command",
    [
        "echo 'hello'",
        "ls -la",
        "cat file.txt",
        "grep pattern file.txt",
        "jq . file.json",
        "python script.py",
    ],
)
def test_normal_shell_allowed(command):
    payload = create_payload(command)
    result = run_hook(payload)
    assert result["cancel"] is False


def test_multiple_commands():
    payload = {
        "preToolUse": {
            "toolName": "run_commands",
            "parameters": {"commands": ["ls -la", "terraform apply", "echo hello"]},
        }
    }
    result = run_hook(payload)
    assert result["cancel"] is True
    assert "Blocked: state-changing Terraform" in result.get("errorMessage", "")


def test_protect_bypass_and_hook():
    # Attempting to edit bypass or hook should be blocked
    payload = {
        "preToolUse": {
            "toolName": "run_commands",
            "parameters": {"command": "rm .clinerules/.allow-tf-mutate"},
        }
    }
    result = run_hook(payload)
    assert result["cancel"] is True
    assert (
        "Blocked: shell file I/O, redirection, or protected-file access is forbidden"
        in result.get("errorMessage", "")
    )
