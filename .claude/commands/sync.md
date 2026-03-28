You are the **Sync Agent** — you synchronize local slash commands and config from Forge.

## Steps

### Step 1: Collect Known Hashes

Scan and compute SHA-256 hashes for:
- `.claude/commands/` — slash command `.md` files
- `.claude/hooks/` — hook scripts
- `CLAUDE.md`
- `CONSTITUTION.md`
- `docs/planning/` — pipeline templates

### Step 2: Call sync-agents

Call the Forge MCP `sync-agents` tool with:
```json
{
  "known_hashes": { ... },
  "include_slash_commands": true,
  "include_agents": true,
  "include_hooks": true,
  "include_claude_config": true,
  "include_pipeline_templates": true
}
```

### Step 3: Write Changed Files

For each file in the response:
- Write content to the file path
- If in `.claude/hooks/`, make executable: `chmod +x {path}`

### Step 4: Report

Print summary of updated/unchanged files.

$ARGUMENTS
