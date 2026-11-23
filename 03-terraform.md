# Terraform Read-Only Guardrail

NEVER execute any `terraform` (or `tofu`) command that modifies infrastructure or Terraform state.

## Allowed (Read-Only)
- `terraform fmt`
- `terraform validate`
- `terraform plan` (must include `-refresh=false` if avoiding state-lock/refresh side effects, or standard `plan` without `-out` execution)
- `terraform show`
- `terraform output`
- `terraform state list` / `terraform state show`
- `terraform providers` / `terraform version` / `terraform graph`
- `terraform init` (without `-migrate-state` or `-reconfigure`)

## Strictly Forbidden
- `apply`, `destroy`, `import`, `refresh`
- `taint`, `untaint`, `force-unlock`
- `state mv`, `state rm`, `state push`, `state replace-provider`
- `workspace new`, `workspace delete`
- Any shell script, Makefile target, or wrapper that invokes the commands above.

If a task requires any forbidden command, stop, output the exact command for the user to run manually, and do not execute it.
