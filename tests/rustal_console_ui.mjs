#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const repository = resolve(fileURLToPath(new URL("..", import.meta.url)));
const appRoot = join(repository, "apps/scorchkit-console");
const binary = join(appRoot, "target/debug/scorchkit-console");
const cssPath = join(appRoot, "assets/console.css");
const jsPath = join(appRoot, "assets/console.js");
const templatesPath = join(appRoot, "templates");
const digestPath = join(repository, "tests/fixtures/console/console.css.sha256");
const mode = process.argv[2];

const TOKEN = ["console", "test", "bearer", "value", "not", "secret"].join("-");
const ENGAGEMENT = "b1382ed4-0ad0-45a2-afd6-550c0d947566";
const PROJECT = "7f7202f4-9620-43f0-9e14-075099545d6f";
const TARGET = "4338d3d4-e6e4-4ab5-8cb8-73d28ec835ae";
const JOB = "482f8eaf-b10e-4eb2-9c88-f3ec6b55e38f";
const FINDING = "f47fd4fb-a099-4b83-91bb-59967e4b7c08";
const SCAN = "aff167d3-c693-46af-b8e4-e37512566390";
const MALICIOUS = '<img src=x onerror="document.body.dataset.pwned=1">';
const EVIDENCE_ID = "a".repeat(64);

function fail(message) {
  process.stderr.write(`Rustal console check failed: ${message}\n`);
  process.exitCode = 1;
}

function check(condition, message) {
  if (!condition) throw new Error(message);
}

function staticChecks() {
  const css = readFileSync(cssPath, "utf8");
  const script = readFileSync(jsPath, "utf8");
  const templates = readdirSync(templatesPath)
    .filter((name) => name.endsWith(".html"))
    .sort()
    .map((name) => readFileSync(join(templatesPath, name), "utf8"))
    .join("\n");
  const digest = createHash("sha256").update(css).digest("hex");
  const expected = readFileSync(digestPath, "utf8").trim();
  check(digest === expected, `reviewed console CSS digest drifted (expected ${expected}, got ${digest})`);

  for (const [pattern, label] of [
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
    [/https?:\/\//iu, "remote URL"]
  ]) {
    check(!pattern.test(script), `console script contains forbidden ${label}`);
  }
  for (const required of [
    "textContent",
    "CSS.escape",
    "EventSource",
    "@media (max-width: 760px)",
    "@media (prefers-reduced-motion: no-preference)",
    "@media (forced-colors: active)",
    ":focus-visible"
  ]) {
    check(css.includes(required) || script.includes(required), `console assets are missing ${required}`);
  }
  check(!templates.includes("|safe"), "console templates bypass HTML escaping");
  check(!templates.includes("SCORCHKIT_CONTROL_TOKEN"), "console templates mention the control bearer");
  check(!templates.includes("engagement/edit"), "console templates expose engagement mutation");
  check(!/<script(?![^>]*\bsrc=)[^>]*>/iu.test(templates), "console templates contain inline script");
  for (const match of templates.matchAll(/\b(?:href|src|action)="([^"]+)"/giu)) {
    check(match[1].startsWith("/") || match[1].startsWith("#"), `non-local template URL: ${match[1]}`);
  }
  process.stdout.write("Rustal console CSS and source policy: PASS\n");
}

function engagement() {
  return {
    id: ENGAGEMENT,
    name: "Dogfood engagement",
    enabled: true,
    expiresAt: "2026-09-30T12:00:00Z",
    capabilities: ["scan", "triage"],
    effects: ["active_safe"]
  };
}

function project() {
  return {
    id: PROJECT,
    name: "Dogfood API",
    description: MALICIOUS,
    createdAt: "2026-08-24T12:00:00Z",
    updatedAt: "2026-08-24T12:30:00Z"
  };
}

function target() {
  return {
    id: TARGET,
    projectId: PROJECT,
    url: "https://app.example.test/",
    label: "Primary application",
    createdAt: "2026-08-24T12:00:00Z"
  };
}

function job() {
  return {
    id: JOB,
    rootJobId: JOB,
    attempt: 1,
    state: "queued",
    revision: 2,
    target: "https://app.example.test/",
    profile: "standard",
    progress: {
      totalModules: 3,
      activeModules: ["nuclei"],
      completedModules: ["headers"],
      skippedModules: ["zap"],
      failedModules: [],
      findingCount: 1
    },
    createdAt: "2026-08-24T12:00:00Z",
    updatedAt: "2026-08-24T12:30:00Z"
  };
}

function finding() {
  return {
    id: FINDING,
    projectId: PROJECT,
    scanId: SCAN,
    fingerprint: "legacy-fingerprint",
    identitySchema: "scorchkit.finding-identity/v1",
    stableIdentity: "finding:dogfood:authorization",
    correlationKeys: { rule: "authz-001" },
    status: "new",
    statusNote: "Needs ownership confirmation",
    seenCount: 2,
    firstSeen: "2026-08-24T12:00:00Z",
    lastSeen: "2026-08-24T12:30:00Z",
    foundAt: "2026-08-24T12:00:00Z",
    canonical: {
      title: MALICIOUS,
      severity: "high quiet",
      appsec: {
        scanner: "nuclei",
        evidence: [{ kind: "text", text: "cross-tenant response" }],
        agent_analysis: [{ schema: "scorchkit.agent-analysis/v1", conclusion: "plausible" }]
      }
    },
    triage: {
      schema: "scorchkit.finding-triage/v1",
      currentState: "needs_context",
      subject: {
        projectIdentity: "project:dogfood",
        findingIdentity: "finding:dogfood:authorization",
        ruleIdentity: "authz-001",
        targetIdentity: "https://app.example.test/accounts/{id}"
      },
      transitions: [{ state: "needs_context", reason: "verify ownership" }],
      correlations: [{ decision: "related", evidenceIds: [EVIDENCE_ID] }],
      suppressions: [{ scope: "exact", active: true }],
      activeSuppressionIds: ["suppression:1"]
    }
  };
}

function evidence() {
  return {
    id: "a30cc483-b33e-4ef4-a53a-501918472187",
    findingId: FINDING,
    scanId: SCAN,
    evidenceSchema: "scorchkit.evidence/v1",
    evidenceIdentity: EVIDENCE_ID,
    canonical: { kind: "http", status: 200, body: MALICIOUS }
  };
}

function report() {
  return {
    schemaVersion: "scorchkit.project-report/v1",
    project: project(),
    targetCount: 1,
    scanCount: 4,
    findingCount: 1,
    severityCounts: { high: 1 },
    triageStateCounts: { needs_context: 1 },
    activeSuppressedCount: 1,
    generatedAt: "2026-08-24T13:00:00Z"
  };
}

function success(kind, value) {
  return { outcome: "success", value: { kind, value } };
}

function outcome(request) {
  const operation = request.operation?.operation;
  switch (operation?.name) {
    case "get_engagement": return success("engagement", engagement());
    case "list_projects": return success("projects", { items: [project()], nextCursor: "next-project-page" });
    case "get_project": return success("project", project());
    case "list_targets": return success("targets", { items: [target()], nextCursor: null });
    case "list_jobs": return success("jobs", { items: [job()], nextCursor: null });
    case "get_job": return success("job", job());
    case "list_findings": return success("findings", { items: [finding()], nextCursor: null });
    case "get_finding": return success("finding", finding());
    case "list_evidence": return success("evidence", { items: [evidence()], nextCursor: null });
    case "get_project_report": return success("report", report());
    case "start_job": return success("job", job());
    default: return success("acknowledged", { changed: true, affected: 1 });
  }
}

async function reservePort() {
  const server = createServer();
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  check(address && typeof address === "object", "port reservation did not return an address");
  await new Promise((resolveClose) => server.close(resolveClose));
  return address.port;
}

async function startControlMock() {
  const commands = [];
  const streams = new Set();
  const server = createServer((request, response) => {
    if (request.headers.authorization !== `Bearer ${TOKEN}`) {
      response.writeHead(401, { "content-type": "text/plain" });
      response.end("unauthorized");
      return;
    }
    if (request.method === "GET" && request.url?.startsWith("/v1/events")) {
      response.writeHead(200, {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-store",
        connection: "keep-alive"
      });
      response.write("retry: 250\n\n");
      streams.add(response);
      request.once("close", () => streams.delete(response));
      return;
    }
    if (request.method !== "POST" || request.url !== "/v1/control") {
      response.writeHead(404, { "content-type": "text/plain" });
      response.end("not found");
      return;
    }
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 128 * 1024) request.destroy();
    });
    request.on("end", () => {
      try {
        const envelope = JSON.parse(body);
        if (envelope.operation?.class === "command") commands.push(envelope.operation.operation);
        const payload = {
          schemaVersion: "scorchkit.control/v1",
          requestId: envelope.requestId,
          principal: { kind: "authenticated_bearer", subject: "console-browser", engagementId: ENGAGEMENT },
          result: outcome(envelope)
        };
        response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        response.end(JSON.stringify(payload));
      } catch (error) {
        response.writeHead(400, { "content-type": "text/plain" });
        response.end("invalid request");
      }
    });
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  check(address && typeof address === "object", "control mock did not bind loopback");
  return {
    origin: `http://127.0.0.1:${address.port}`,
    commands,
    emitJobState(state) {
      const event = {
        schemaVersion: "scorchkit.control.event/v1",
        sequence: 1,
        kind: "job_changed",
        resourceType: "job",
        resourceId: JOB,
        resourceRevision: 3,
        occurredAt: "2026-08-24T13:01:00Z",
        payload: { state }
      };
      const frame = `event: control\nid: 1\ndata: ${JSON.stringify(event)}\n\n`;
      for (const stream of streams) stream.write(frame);
    },
    async close() {
      for (const stream of streams) stream.end();
      server.closeAllConnections();
      await new Promise((resolveClose) => server.close(resolveClose));
    }
  };
}

async function waitFor(probe, message, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const value = await probe();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`${message}${lastError ? `: ${lastError.message}` : ""}`);
}

async function startConsole(control) {
  check(existsSync(binary), `console binary is missing: ${binary}`);
  const port = await reservePort();
  const output = { stdout: "", stderr: "", status: null };
  const child = spawn(binary, [], {
    cwd: repository,
    env: {
      ...process.env,
      RUST_LOG: "warn",
      SCORCHKIT_CONSOLE_BIND: `127.0.0.1:${port}`,
      SCORCHKIT_CONSOLE_CONTROL_URL: control.origin,
      SCORCHKIT_CONSOLE_ENGAGEMENT_ID: ENGAGEMENT,
      SCORCHKIT_CONSOLE_TOKEN_ENV: "SCORCHKIT_CONSOLE_TEST_TOKEN",
      SCORCHKIT_CONSOLE_TEST_TOKEN: TOKEN
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { output.stdout = (output.stdout + chunk).slice(-2 * 1024 * 1024); });
  child.stderr.on("data", (chunk) => { output.stderr = (output.stderr + chunk).slice(-2 * 1024 * 1024); });
  child.once("close", (status) => { output.status = status; });
  const origin = `http://127.0.0.1:${port}`;
  await waitFor(async () => {
    if (output.status !== null) throw new Error(`console exited ${output.status}: ${output.stderr.slice(-1200)}`);
    const response = await fetch(`${origin}/`);
    return response.status === 200;
  }, "console did not become ready", 20000);
  return {
    origin,
    diagnostics() {
      return `${output.stdout}\n${output.stderr}`.slice(-2000);
    },
    async close() {
      if (output.status !== null) return;
      child.kill("SIGTERM");
      await Promise.race([
        new Promise((resolveExit) => child.once("close", resolveExit)),
        new Promise((resolveKill) => setTimeout(() => { child.kill("SIGKILL"); resolveKill(); }, 3000))
      ]);
    }
  };
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
  throw new Error("Google Chrome or Chromium is required for console UI evidence");
}

function driverPath() {
  const configured = process.env.SCORCHKIT_CHROMEDRIVER;
  if (configured) {
    check(existsSync(configured), `SCORCHKIT_CHROMEDRIVER does not exist: ${configured}`);
    return configured;
  }
  for (const candidate of [join(process.env.HOME || "", ".local/bin/chromedriver"), "/usr/bin/chromedriver"]) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error("ChromeDriver is required for console UI evidence");
}

async function startDriver() {
  const port = await reservePort();
  const output = { stdout: "", stderr: "", status: null };
  const child = spawn(driverPath(), [`--port=${port}`, "--allowed-ips=127.0.0.1"], {
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { output.stdout = (output.stdout + chunk).slice(-1024 * 1024); });
  child.stderr.on("data", (chunk) => { output.stderr = (output.stderr + chunk).slice(-1024 * 1024); });
  child.once("close", (status) => { output.status = status; });
  const endpoint = `http://127.0.0.1:${port}`;
  await waitFor(async () => {
    if (output.status !== null) throw new Error(`ChromeDriver exited ${output.status}: ${output.stderr.slice(-1200)}`);
    const response = await fetch(`${endpoint}/status`);
    return response.ok;
  }, "ChromeDriver did not become ready");

  async function command(method, path, body) {
    const response = await fetch(`${endpoint}${path}`, {
      method,
      headers: body === undefined ? undefined : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const payload = await response.json();
    if (!response.ok || payload.value?.error) {
      throw new Error(payload.value?.message || `WebDriver ${method} ${path} failed with ${response.status}`);
    }
    return payload.value;
  }

  return {
    command,
    async close() {
      if (output.status !== null) return;
      child.kill("SIGTERM");
      await Promise.race([
        new Promise((resolveExit) => child.once("close", resolveExit)),
        new Promise((resolveKill) => setTimeout(() => { child.kill("SIGKILL"); resolveKill(); }, 3000))
      ]);
    }
  };
}

async function createSession(driver, extraFlags = []) {
  const profile = mkdtempSync(join(tmpdir(), "scorchkit-console-browser-"));
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
    ...extraFlags
  ];
  if (typeof process.getuid === "function" && process.getuid() === 0) flags.push("--no-sandbox");
  const created = await driver.command("POST", "/session", {
    capabilities: {
      alwaysMatch: {
        browserName: "chrome",
        "goog:chromeOptions": { binary: browserPath(), args: flags }
      }
    }
  });
  const id = created.sessionId;
  check(typeof id === "string" && id.length > 0, "ChromeDriver omitted the session ID");
  return {
    async navigate(url) {
      await driver.command("POST", `/session/${id}/url`, { url });
    },
    async execute(script, args = []) {
      return driver.command("POST", `/session/${id}/execute/sync`, { script, args });
    },
    async wait(script, message, timeoutMs = 15000) {
      return waitFor(() => this.execute(script), message, timeoutMs);
    },
    async close() {
      try {
        await driver.command("DELETE", `/session/${id}`);
      } finally {
        rmSync(profile, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      }
    }
  };
}

async function withHarness(run) {
  const control = await startControlMock();
  let consoleServer;
  let driver;
  try {
    consoleServer = await startConsole(control);
    driver = await startDriver();
    await run({ control, consoleServer, driver });
  } finally {
    if (driver) await driver.close();
    if (consoleServer) await consoleServer.close();
    await control.close();
  }
}

async function browserCheck() {
  await withHarness(async ({ control, consoleServer, driver }) => {
    const session = await createSession(driver, ["--window-size=1100,900"]);
    try {
      await session.navigate(`${consoleServer.origin}/`);
      const dashboard = await session.execute(`
        return {
          text: document.body.innerText,
          projects: document.querySelectorAll('a[href^="/projects/"]').length,
          jobs: document.querySelectorAll('[data-job-id]').length,
          secret: document.documentElement.outerHTML.includes(${JSON.stringify(TOKEN)})
        };`);
      check(dashboard.text.includes("Dogfood engagement"), "dashboard omitted engagement posture");
      check(dashboard.text.includes("Read-only authority"), "dashboard widened engagement authority");
      check(dashboard.projects === 1 && dashboard.jobs === 1, "dashboard navigation rows are incomplete");
      check(!dashboard.secret, "control bearer reached browser markup");

      control.emitJobState("running");
      await session.wait(
        `return document.querySelector('[data-job-id="${JOB}"] [data-job-state]')?.textContent === 'running';`,
        "browser did not receive the monotonic job event",
        20000
      );

      await session.navigate(`${consoleServer.origin}/projects/${PROJECT}`);
      const projectView = await session.execute("return document.body.innerText;");
      check(projectView.includes("Registered targets") && projectView.includes("Canonical findings"), "project drill-down is incomplete");

      await session.navigate(`${consoleServer.origin}/findings/${FINDING}`);
      const findingView = await session.execute(`
        return {
          text: document.body.innerText,
          images: document.querySelectorAll('img').length,
          pwned: Boolean(document.body.dataset.pwned),
          form: Boolean(document.querySelector('form[action$="/triage"]')),
          severityClasses: Array.from(document.querySelector('.severity').classList)
        };`);
      for (const label of ["Scanner record", "Model analysis", "Correlation decisions", "Suppression history"]) {
        check(findingView.text.includes(label), `finding drill-down omitted ${label}`);
      }
      check(
        findingView.severityClasses.join(" ") === "severity unknown",
        "canonical severity injected CSS classes"
      );
      check(findingView.images === 0 && !findingView.pwned, "canonical text became active markup");
      check(findingView.form, "triage form is missing");
      await session.execute(`
        const form = document.querySelector('form[action$="/triage"]');
        form.querySelector('select[name="state"]').value = 'validated';
        form.querySelector('textarea[name="reason"]').value = 'browser proof';
        form.requestSubmit();
        return true;`);
      try {
        await session.wait(
          "return document.body.innerText.includes('Triage decision appended through the control API.');",
          "triage submission did not return its API-backed status"
        );
      } catch (error) {
        const page = await session.execute("return {url: location.href, text: document.body.innerText.slice(0, 1200)};");
        throw new Error(`${error.message}; page=${JSON.stringify(page)}; commands=${JSON.stringify(control.commands)}; console=${consoleServer.diagnostics()}`);
      }
      const transition = control.commands.find((command) => command.name === "transition_finding");
      check(transition?.params?.state === "validated", "browser triage did not send the exact state");
      check(transition?.params?.reason === "browser proof", "browser triage did not send the exact reason");
      check(transition?.params?.evidence_ids?.[0] === EVIDENCE_ID, "browser triage lost its evidence identity");

      await session.navigate(`${consoleServer.origin}/jobs/${JOB}`);
      const jobView = await session.execute("return document.body.innerText;");
      check(jobView.includes("Degraded: 0 failed, 1 skipped"), "job view hid degraded coverage");
      check(jobView.includes("Request cancellation"), "job lifecycle action is missing");
    } finally {
      await session.close();
    }
  });
  process.stdout.write("Rustal console browser interaction: PASS\n");
}

async function renderCheck() {
  await withHarness(async ({ consoleServer, driver }) => {
    const mobile = await createSession(driver, ["--window-size=360,800"]);
    try {
      await mobile.navigate(`${consoleServer.origin}/`);
      const result = await mobile.execute(`
        return {
          overflow: document.documentElement.scrollWidth > window.innerWidth,
          main: Boolean(document.querySelector('main#content')),
          status: Boolean(document.querySelector('[aria-live="polite"]')),
          labels: document.querySelectorAll('label').length,
          title: document.title
        };`);
      check(!result.overflow, "mobile dashboard has horizontal overflow");
      check(result.main && result.status && result.labels >= 4, "mobile dashboard semantics are incomplete");
      check(result.title.includes("ScorchKit Console"), "mobile dashboard title is missing");
    } finally {
      await mobile.close();
    }

    const accessible = await createSession(driver, [
      "--window-size=1100,900",
      "--force-high-contrast",
      "--force-prefers-reduced-motion"
    ]);
    try {
      await accessible.navigate(`${consoleServer.origin}/findings/${FINDING}`);
      const result = await accessible.execute(`
        const widths = [...document.querySelectorAll('*')].map((element) => ({
          name: element.tagName + '.' + element.className,
          right: element.getBoundingClientRect().right,
          width: element.scrollWidth
        })).sort((left, right) => Math.max(right.right, right.width) - Math.max(left.right, left.width));
        return {
          overflow: document.documentElement.scrollWidth > window.innerWidth,
          scrollWidth: document.documentElement.scrollWidth,
          innerWidth: window.innerWidth,
          widest: widths[0],
          forced: matchMedia('(forced-colors: active)').matches,
          reduced: matchMedia('(prefers-reduced-motion: reduce)').matches,
          text: document.body.innerText,
          focusable: document.querySelectorAll('a[href],button,input,select,textarea').length
        };`);
      check(!result.overflow, `finding render has horizontal overflow: ${JSON.stringify(result)}`);
      check(result.forced, "high-contrast representative render was not active");
      check(result.reduced, "reduced-motion representative render was not active");
      check(result.focusable >= 8, "finding render omitted keyboard controls");
      check(result.text.includes("Evidence") && result.text.includes("Triage"), "finding render omitted evidence or triage");
    } finally {
      await accessible.close();
    }
  });
  process.stdout.write("Rustal console representative renders: PASS\n");
}

async function main() {
  if (mode === "css") return staticChecks();
  if (mode === "browser") return browserCheck();
  if (mode === "render") return renderCheck();
  throw new Error("usage: node tests/rustal_console_ui.mjs <browser|render|css>");
}

main().catch((error) => fail(error.message));
