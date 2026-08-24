#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const repository = resolve(fileURLToPath(new URL("..", import.meta.url)));
const componentPath = join(repository, "src/mcp/conversation-workbench.html");
const digestPath = join(repository, "tests/fixtures/mcp/conversation-workbench.css.sha256");
const component = readFileSync(componentPath, "utf8");
const mode = process.argv[2];

function fail(message) {
  process.stderr.write(`conversation workbench check failed: ${message}\n`);
  process.exitCode = 1;
}

function check(condition, message) {
  if (!condition) throw new Error(message);
}

function styleSource() {
  const match = component.match(/<style>([\s\S]*?)<\/style>/u);
  check(match !== null, "component must contain one inline style block");
  check(component.match(/<style>/gu)?.length === 1, "component must contain exactly one style block");
  return match[1];
}

function staticChecks() {
  const digest = createHash("sha256").update(styleSource()).digest("hex");
  const expected = readFileSync(digestPath, "utf8").trim();
  check(digest === expected, `reviewed CSS digest drifted (expected ${expected}, got ${digest})`);

  const forbidden = [
    [/\binnerHTML\b/u, "innerHTML"],
    [/\bouterHTML\b/u, "outerHTML"],
    [/insertAdjacentHTML/u, "insertAdjacentHTML"],
    [/\beval\s*\(/u, "eval"],
    [/new\s+Function\b/u, "new Function"],
    [/\bfetch\s*\(/u, "fetch"],
    [/\bXMLHttpRequest\b/u, "XMLHttpRequest"],
    [/\bWebSocket\b/u, "WebSocket"],
    [/\blocalStorage\b/u, "localStorage"],
    [/\bsessionStorage\b/u, "sessionStorage"],
    [/document\.cookie/u, "document.cookie"],
    [/<(?:link|img|iframe)\b/iu, "external-capable asset element"],
    [/\b(?:src|href)\s*=/iu, "external-capable asset attribute"],
    [/https?:\/\//iu, "remote URL"]
  ];
  for (const [pattern, label] of forbidden) {
    check(!pattern.test(component), `component contains forbidden ${label}`);
  }
  for (const required of [
    "Content-Security-Policy",
    "event.source !== window.parent",
    "textContent",
    "@media (max-width: 640px)",
    "@media (prefers-reduced-motion: reduce)",
    "@media (forced-colors: active)",
    'role="status"',
    'aria-live="polite"',
    ":focus-visible"
  ]) {
    check(component.includes(required), `component is missing ${required}`);
  }
  process.stdout.write("conversation workbench CSS and source policy: PASS\n");
}

const malicious = '<img src=x onerror="document.body.dataset.pwned=1">';
const fixtures = {
  posture: {
    schemaVersion: "scorchkit.mcp.tool-result/v1",
    tool: "project_status",
    outcome: "success",
    result: {
      project_name: "Dogfood API",
      scan_summary: {
        total_scans: 7,
        latest_scan_date: "2026-08-24T12:00:00Z",
        latest_scan_id: "22222222-2222-4222-8222-222222222222",
        scans_last_30_days: 6
      },
      finding_summary: { total_findings: 12, active_findings: 4, resolved_findings: 8 },
      severity_breakdown: [
        { severity: "critical", count: 1 },
        { severity: "high", count: 3 },
        { severity: "medium", count: 5 },
        { severity: "low", count: 3 }
      ],
      status_breakdown: [
        { status: "new", count: 2 },
        { status: "acknowledged", count: 2 },
        { status: "remediated", count: 8 }
      ],
      regressions: [{
        id: "33333333-3333-4333-8333-333333333333",
        title: "Authorization regression",
        severity: "high",
        module_id: "dogfood",
        affected_target: "/api/accounts/{id}",
        previous_status: "verified"
      }],
      top_unresolved: [{
        id: "11111111-1111-4111-8111-111111111111",
        title: "Broken object authorization",
        severity: "high",
        status: "new",
        first_seen: "2026-08-24T12:00:00Z",
        seen_count: 2
      }],
      trend: "improving",
      mttr_days: 3.4
    }
  },
  finding: {
    schemaVersion: "scorchkit.mcp.tool-result/v1",
    tool: "finding_show",
    outcome: "success",
    result: {
      id: "11111111-1111-4111-8111-111111111111",
      severity: "high",
      title: malicious,
      description: "An authenticated user can read another tenant record.",
      affected_target: "/api/accounts/{id}",
      evidence: malicious,
      remediation: "Enforce ownership in the canonical policy layer.",
      owasp_category: "A01:2021",
      cwe_id: "CWE-639",
      confidence: 0.98,
      seen_count: 2,
      status: "new",
      raw_finding: {
        appsec: {
          evidence: [{ schema: "scorchkit.evidence/v1", payload: { kind: "text", text: malicious } }],
          agent_analysis: [{ schema: "scorchkit.agent-analysis/v1", label: "model-generated", conclusion: "Plausible" }]
        }
      },
      triage: { currentState: "needs_context", transitions: [], correlations: [], suppressions: [] }
    }
  },
  attack: {
    schemaVersion: "scorchkit.mcp.tool-result/v1",
    tool: "correlate_findings",
    outcome: "success",
    result: {
      schema: "scorchkit.attack-paths/v1",
      project: "Dogfood API",
      total_findings_available: 12,
      total_findings_analyzed: 12,
      status: "complete",
      attack_paths_found: 1,
      attack_paths: [{ title: "Tenant record to signing key", finding_ids: ["a", "b"] }],
      gaps: [{ kind: "missing_runtime_proof", target: "/api/accounts/{id}" }],
      legacy_unverified_attack_chains: { status: "separate", attack_chains_found: 0, chains: [] }
    }
  }
};

function scriptValue(value) {
  return JSON.stringify(value).replaceAll("</", "<\\/");
}

function parentDocument(caseName, interaction) {
  const fixture = fixtures[caseName];
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Workbench harness</title></head>
<body><output id="result">PENDING:${caseName}</output><div id="mount"></div>
<script>
"use strict";
const fixture = ${scriptValue(fixture)};
const caseName = ${scriptValue(caseName)};
const interaction = ${interaction ? "true" : "false"};
const output = document.getElementById("result");
let child;
let initialized = false;
let resultSent = false;
let timeoutId;
function finish(message) { output.textContent = message; if (timeoutId) clearTimeout(timeoutId); }
function send(message) { child.contentWindow.postMessage(message, "*"); }
function verifyRender() {
  const doc = child.contentDocument;
  if (!doc || doc.getElementById("connection-state")?.textContent !== "Evidence ready") return false;
  if (!doc.querySelector("main") || !doc.querySelector('[role="status"][aria-live="polite"]')) throw new Error("semantic status region missing");
  if (caseName === "posture") {
    if (!doc.body.textContent.includes("Dogfood API") || doc.querySelectorAll(".metric").length !== 8) throw new Error("posture view incomplete");
    if (!doc.body.textContent.includes("Active findings") || !doc.body.textContent.includes("Scans in 30 days")) throw new Error("canonical posture fields missing");
    if (!doc.body.textContent.includes("Latest scan") || !doc.body.textContent.includes("Authorization regression")) throw new Error("scan or regression detail missing");
  }
  if (caseName === "finding") {
    if (!doc.body.textContent.includes(fixture.result.title)) throw new Error("finding title not rendered as text");
    if (doc.querySelector("img") || doc.body.dataset.pwned) throw new Error("untrusted finding text became active markup");
    if (!doc.body.textContent.includes("model-generated") || !doc.body.textContent.includes("Triage history")) throw new Error("finding evidence layers missing");
  }
  if (caseName === "attack") {
    if (!doc.body.textContent.includes("Canonical attack paths") || !doc.body.textContent.includes("Evidence gaps")) throw new Error("attack-path layers missing");
  }
  return true;
}
window.addEventListener("message", (event) => {
  if (event.source !== child.contentWindow || !event.data || event.data.jsonrpc !== "2.0") return;
  const message = event.data;
  if (message.method === "ui/initialize") {
    if (message.params?.protocolVersion !== "2026-01-26") return finish("FAIL:protocol");
    send({ jsonrpc: "2.0", id: message.id, result: { hostContext: { theme: "dark", displayMode: "inline" } } });
    return;
  }
  if (message.method === "ui/notifications/initialized") {
    initialized = true;
    send({ jsonrpc: "2.0", method: "ui/notifications/tool-input", params: { arguments: { fixture: caseName } } });
    send({ jsonrpc: "2.0", method: "ui/notifications/tool-result", params: { structuredContent: fixture } });
    resultSent = true;
    setTimeout(() => {
      try {
        if (!verifyRender()) return finish("FAIL:not-rendered");
        if (!interaction) return finish("PASS:" + caseName);
        const button = child.contentDocument.getElementById("update-finding");
        const select = child.contentDocument.getElementById("finding-status");
        if (!button) return finish("FAIL:action-missing");
        if (!select) return finish("FAIL:status-control-missing");
        select.value = "acknowledged";
        button.focus();
        button.click();
      } catch (error) { finish("FAIL:" + error.message); }
    }, 100);
    return;
  }
  if (message.method === "tools/call") {
    const args = message.params?.arguments;
    if (message.params?.name !== "finding_update_status" ||
        args?.id !== fixture.result.id || args?.status !== "acknowledged") return finish("FAIL:unsafe-action");
    send({ jsonrpc: "2.0", id: message.id, result: { isError: false, content: [{ type: "text", text: "updated" }] } });
    setTimeout(() => {
      const text = child.contentDocument.getElementById("status")?.textContent || "";
      if (!text.includes("standard ScorchKit tool path")) return finish("FAIL:action-status");
      send({
        jsonrpc: "2.0",
        method: "ui/notifications/tool-result",
        params: { structuredContent: { schemaVersion: "untrusted", tool: "finding_show", outcome: "success", result: { title: fixture.result.title } } }
      });
      setTimeout(() => {
        const doc = child.contentDocument;
        const safe = doc.querySelector(".empty h2")?.textContent === "Workbench data unavailable" && !doc.querySelector("img") && !doc.body.dataset.pwned;
        finish(safe ? "PASS:browser" : "FAIL:unsafe-fallback");
      }, 50);
    }, 50);
  }
});
child = document.createElement("iframe");
child.title = "ScorchKit workbench under test";
child.src = "/app";
document.getElementById("mount").append(child);
timeoutId = setTimeout(() => finish("FAIL:timeout:" + initialized + ":" + resultSent), 3500);
</script></body></html>`;
}

function browserPath() {
  const configured = process.env.SCORCHKIT_BROWSER;
  if (configured) {
    check(existsSync(configured), `SCORCHKIT_BROWSER does not exist: ${configured}`);
    return configured;
  }
  for (const candidate of ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"]) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error("Google Chrome or Chromium is required for delivery UI evidence");
}

async function runBrowserCase(caseName, interaction, extraFlags = []) {
  const server = createServer((request, response) => {
    response.setHeader("Cache-Control", "no-store");
    if (request.url === "/app") {
      response.setHeader("Content-Type", "text/html;profile=mcp-app; charset=utf-8");
      response.end(component);
      return;
    }
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    response.end(parentDocument(caseName, interaction));
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  check(address && typeof address === "object", "loopback harness did not bind");
  const profile = mkdtempSync(join(tmpdir(), "scorchkit-workbench-"));
  try {
    const flags = [
      "--headless=new",
      "--disable-gpu",
      "--disable-dev-shm-usage",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
      "--no-default-browser-check",
      "--no-first-run",
      "--metrics-recording-only",
      "--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1",
      `--user-data-dir=${profile}`,
      "--dump-dom",
      "--virtual-time-budget=5000",
      ...extraFlags
    ];
    if (typeof process.getuid === "function" && process.getuid() === 0) flags.push("--no-sandbox");
    flags.push(`http://127.0.0.1:${address.port}/`);
    const result = await new Promise((resolveRun, rejectRun) => {
      const childProcess = spawn(browserPath(), flags, { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        childProcess.kill("SIGKILL");
      }, 30000);
      childProcess.stdout.setEncoding("utf8");
      childProcess.stderr.setEncoding("utf8");
      childProcess.stdout.on("data", (chunk) => {
        stdout += chunk;
        if (stdout.length > 10 * 1024 * 1024) childProcess.kill("SIGKILL");
      });
      childProcess.stderr.on("data", (chunk) => {
        stderr += chunk;
        if (stderr.length > 10 * 1024 * 1024) childProcess.kill("SIGKILL");
      });
      childProcess.once("error", (error) => {
        clearTimeout(timer);
        rejectRun(error);
      });
      childProcess.once("close", (status) => {
        clearTimeout(timer);
        if (timedOut) {
          rejectRun(new Error("browser timed out after 30 seconds"));
          return;
        }
        resolveRun({ status, stdout, stderr });
      });
    });
    check(result.status === 0, `browser exited ${result.status}: ${result.stderr.slice(-1200)}`);
    const expected = interaction ? "PASS:browser" : `PASS:${caseName}`;
    check(result.stdout.includes(expected), `browser evidence missing ${expected}`);
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
    rmSync(profile, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
}

async function main() {
  if (mode === "css") {
    staticChecks();
    return;
  }
  if (mode === "browser") {
    await runBrowserCase("finding", true, ["--window-size=1024,900"]);
    process.stdout.write("conversation workbench browser interaction: PASS\n");
    return;
  }
  if (mode === "render") {
    await runBrowserCase("posture", false, ["--window-size=360,800"]);
    await runBrowserCase("finding", false, ["--window-size=1024,900", "--force-high-contrast"]);
    await runBrowserCase("attack", false, ["--window-size=1024,900"]);
    process.stdout.write("conversation workbench representative renders: PASS\n");
    return;
  }
  throw new Error("usage: node tests/conversation_workbench_ui.mjs <browser|render|css>");
}

main().catch((error) => fail(error.message));
