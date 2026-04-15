# 05 — TLS + DNS hygiene for your own domain

**Goal:** run `tls_infra` and `dns_infra` against a domain you operate. Understand each finding. Decide what to fix.

**Time:** ~20 minutes plus however long any fixes take.

**You'll need:** ScorchKit built with `--features infra`. A domain you own — for the examples we'll pretend it's `example.com`; substitute your own.

---

## 1. Why these two modules

Most pentest tooling goes deep on web-app vulnerabilities and treats infrastructure as a checklist of port-scanner output. TLS and DNS hygiene is where many real-world incidents start (see: dangling DNS, expired certs on internal services, missing CAA leading to mis-issued certs). `tls_infra` and `dns_infra` are quick, low-noise probes that catch the common slip-ups.

## 2. Run both probes

```bash
sk infra example.com --modules tls_infra,dns_infra
```

You'll see findings tagged `tls_infra` and `dns_infra`. Each finding has `module_id` set so you can filter the JSON report later.

## 3. Reading TLS infra findings

`tls_infra` probes 8 mail / directory ports by default. Each port produces either:

- **Cert findings** (Critical / High / Medium) — expired, self-signed, weak signature, host mismatch. Same shape as the DAST `ssl` module.
- **Info "TLS probe skipped"** — port closed or service doesn't speak TLS. Expected for hosts that don't run that service. Don't treat these as defects.

The probe list:

| Port | Mode | Service |
|-----:|------|---------|
| 465 | Implicit | SMTPS |
| 636 | Implicit | LDAPS |
| 993 | Implicit | IMAPS |
| 995 | Implicit | POP3S |
| 25 / 587 | STARTTLS | SMTP / Submission |
| 143 | STARTTLS | IMAP |
| 110 | STARTTLS | POP3 |

If you don't run a mail server: most of these will Info-skip. That's fine.

If you do: any cert finding here is real. Mail clients tend to ignore TLS warnings the way browsers used to — meaning a broken cert doesn't surface to your users until something stops working entirely. A Critical or High here is worth fixing today.

## 4. Reading DNS infra findings

Four checks at the zone apex:

| Check | Severity | What it means |
|-------|---------:|---------------|
| Wildcard A/AAAA | Medium | A random nonexistent subdomain resolved. Either intentional (catch-all) or a misconfig that hides typos and biases recon |
| DNSSEC missing | Medium | No `DNSKEY` records. Clients can't verify your DNS answers; an attacker who can inject DNS responses can spoof your domain |
| CAA missing | Low | No `CAA` records. Any publicly-trusted CA can issue certs for your domain — raises the blast radius of a CA compromise or social-engineered issuance |
| NS enumeration | Info | Surfaces the authoritative-server list. Useful for delegation audits |

## 5. What to actually fix

Triage priority:

1. **Any Critical or High TLS finding** — fix today. Expired or weak-sig certs on mail/directory services.
2. **Wildcard DNS** — confirm it's intentional. If yes, document it. If no, replace with explicit subdomain records.
3. **DNSSEC missing** — enable at the registrar + DNS provider. ~30 minutes of work for most providers; eliminates a whole class of attacks.
4. **CAA missing** — add a CAA record naming your CAs. ~5 minutes:

```dns
example.com.    IN  CAA  0 issue "letsencrypt.org"
example.com.    IN  CAA  0 issuewild "letsencrypt.org"
example.com.    IN  CAA  0 iodef "mailto:security@example.com"
```

## 6. Re-scan after fixes

```bash
sk infra example.com --modules tls_infra,dns_infra -o json
mv scorchkit-report.json after.json
sk diff before.json after.json
```

`diff` shows you which findings disappeared (you fixed them), which are still there (more work), and which are new (oops).

## 7. Schedule it

Don't make this a one-time thing. Set up a weekly recurring scan:

```bash
# Requires --features storage at build time and a configured Postgres.
# Positional args: <project> <target> <cron>
sk schedule create my-project example.com "0 9 * * 1" --profile standard
```

Schedules attach to a project, not a bare target — create a project first with `sk project create my-project`. The schedule runs whichever profile you specify; to pin it to just `tls_infra,dns_infra` today, wrap the scan in a cron job or CI schedule (see [tutorial 08 §4](08-ci-cd-integration.md)) until per-schedule module overrides land.

## 8. Where to go next

- **[02 — CVE correlation](02-cve-correlation.md)** — the other big infra story
- **[03 — Unified assess](03-unified-assess.md)** — fold these into a full assessment run

---

## Things that go wrong

| Symptom | Cause | Fix |
|---------|-------|-----|
| Lots of "TLS probe skipped" findings | The host doesn't run mail / directory services | Filter the report — these are Info, not defects |
| `tls_infra` reports cert mismatch on every port | Probing an IP literal, not a hostname | Use the hostname so SNI works correctly |
| `dns_infra` says CAA missing but I have CAA records | Records are at a parent zone, not the queried apex | CAA records must be at the exact zone you query — check `dig example.com CAA` directly |
| `dns_infra` wildcard finding is a false positive | You really do use wildcard routing | Document it; severity is Medium not High because it's often intentional. Future enhancement could let operators acknowledge wildcard-as-intentional in config |
