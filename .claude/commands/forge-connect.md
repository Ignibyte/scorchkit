# Forge Connect — Self-Service Project Registration

You are helping the user register ScorchKit with a Forge RLM server and configure the MCP connection.

## Step 1: Gather Information

Auto-detect from the codebase:
- **Project name**: ScorchKit
- **Framework**: rust
- **Description**: Web application security testing toolkit and orchestrator

Confirm with the user.

## Step 2: Register with Forge

```bash
FORGE_URL="${FORGE_URL:-https://forge.ddev.site}"
```

Call the registration endpoint:

```bash
curl -s -X POST "${FORGE_URL}/api/v1/register" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ScorchKit",
    "framework": "rust",
    "description": "Web application security testing toolkit and orchestrator"
  }'
```

## Step 3: Configure MCP

Write the `mcp_config` from the response to `.mcp.json`.

## Step 4: Verify Connection

Tell the user to restart Claude Code, then verify with `health` MCP tool.

## Important Notes

- API key shown **only once** during registration
- If lost, use `POST /api/v1/projects/rotate-key`
- Run `bootstrap` after connecting

$ARGUMENTS
