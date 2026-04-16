# 04 — Conversational pentest in Claude Code

**Goal:** use ScorchKit's slash commands inside [Claude Code](https://claude.ai/claude-code) to run scans, analyse findings, and triage results in a guided chat.

**Time:** ~20 minutes after Claude Code is installed.

**You'll need:** ScorchKit built. Claude Code installed and authenticated. The ScorchKit repo opened in Claude Code (the slash commands live in `.claude/commands/`).

---

## 1. Why slash commands?

The CLI is fast for operators who already know what they want. Slash commands are slower per scan but **carry the conversation**: ask follow-up questions about a finding, get explanations of OWASP categories, walk through remediation step-by-step. Best for first-time use, training, or assessment days where you want a human-readable trail.

## 2. Open the project in Claude Code

```bash
cd ~/scorchkit
claude
```

Claude Code reads `.claude/commands/*.md` and registers each as a slash command. You'll see the available commands when you type `/`.

## 3. Run a scan with `/scan`

In the Claude Code chat:

```
/scan https://httpbin.org quick
```

`/scan` walks through the scan — picks the profile, asks about auth and proxy if it needs to, runs the scan, then reads the report back to you with explanations. Unlike the bare CLI, it doesn't just dump findings — it groups them, explains *why* each matters, and suggests follow-ups.

Try it with the standard profile too:

```
/scan https://httpbin.org
```

## 4. Analyse with `/analyze`

After a scan, the JSON report sits at `scorchkit-report.json`. Hand it to `/analyze` for a Claude-mediated breakdown:

```
/analyze scorchkit-report.json
```

The command lets you pick a focus:

- **Summary** — executive 3-paragraph overview
- **Prioritize** — risk ranking with attack-chain reasoning
- **Remediate** — tech-specific fix instructions
- **Filter** — separate true positives from likely false positives

Each focus uses a different prompt template; results are written back into the chat for you to discuss.

## 5. SAST: `/code`

Same shape, source-code edition:

```
/code ~/src/my-project
/code ~/src/my-project quick
```

Picks the language automatically, runs the configured SAST tools, surfaces findings.

## 6. Compare scans with `/diff`

After two scans:

```
/diff baseline.json current.json
```

Tells you what's new, what's resolved, what's unchanged. Useful for "did my fix actually fix it?" and "what regressed since last week?"

## 7. Triage with `/finding`

Requires `--features storage` and a configured Postgres. Lets you walk findings through the lifecycle (`new` → `acknowledged` → `remediated` → `verified`):

```
/finding list my-app
/finding list my-app --severity critical
/finding show <finding-id>
/finding status <finding-id> acknowledged
```

`/finding status` walks you through the state machine (`new` → `acknowledged` → `remediated` → `verified`, plus side states like `false_positive`, `wont_fix`, `accepted_risk`).

## 8. Recurring scans with `/schedule`

```
/schedule create my-app https://staging.my-app.com "0 9 * * 1"
/schedule list my-app
/schedule run
```

Three positional args: project, target, cron (standard 5-field cron). Backed by the same cron-style scheduler the CLI uses; the slash command makes it interactive.

## 9. Project management with `/project`

```
/project create my-app
/project status my-app
```

Walks you through creating a project, adding targets, checking posture metrics over time.

## 10. Extending: `/coder`

When you're ready to write a new module, `/coder` is your development assistant — it loads the architecture docs, explains the trait you need to implement, and walks you through the existing patterns:

```
/coder
> I want to add a new SAST tool for Lua
```

## 11. Where to go next

- **[05 — TLS + DNS hygiene](05-tls-and-dns-hygiene.md)** — apply the same workflow to your own infra
- **[06 — Custom modules](06-extending-with-custom-modules.md)** — when `/coder` walks you to the keyboard

---

## Things that go wrong

| Symptom | Cause | Fix |
|---------|-------|-----|
| `/` doesn't show ScorchKit commands | Claude Code didn't pick up `.claude/commands/` | Restart Claude Code from inside the repo |
| `/scan` says "scorchkit not found" | Binary not on PATH | `cargo build --release && export PATH=$PWD/target/release:$PATH` |
| Slash commands feel slow | Each step round-trips to Claude | Use the bare CLI (`sk run`) when you don't need the conversation; mix and match per-task |
