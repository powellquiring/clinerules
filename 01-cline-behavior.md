# 1. FILE OPERATIONS
- Use `read_file`, `write_to_file`, and `replace_in_file` for all file I/O.
- Never read, write, or modify files via `execute_command`.
- In Plan Mode, output plans only in chat; never write plan files.
- Temp scripts: create via `write_to_file` in `/tmp`, run via `execute_command`, then remove.

# 2. TERMINAL EXECUTION
- Commands must be non-interactive (`git --no-pager`, `PAGER=cat`).

# 3. READ-ONLY CONSTRAINTS (GIT, TERRAFORM, AUTH0)
- Only run read-only commands (`git status/log/diff`, `auth0 users search`).
- For any state change, stop and print the exact commands in a code block for manual execution.
