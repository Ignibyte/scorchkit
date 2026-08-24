# ScorchKit Console

`scorchkit-console` is an optional local Rustal frontend for ScorchKit's authenticated v1 control
API. It is deliberately outside the root Cargo workspace: building ScorchKit core does not locate
or compile Rustal, and the console has its own lockfile.

The current source-stack profile requires the sibling Rustal checkout at the exact revision checked
by `bash bin/console.sh preflight`. The helper refuses a different revision or dirty Rustal/derive
source so a path dependency cannot silently change the delivered console.

Start ScorchKit's control API with its normal bearer-authenticated loopback configuration. Then set:

```text
SCORCHKIT_CONSOLE_CONTROL_URL=http://127.0.0.1:7444
SCORCHKIT_CONSOLE_ENGAGEMENT_ID=<the exact configured engagement UUID>
SCORCHKIT_CONSOLE_TOKEN_ENV=SCORCHKIT_CONTROL_TOKEN
SCORCHKIT_CONTROL_TOKEN=<the same 32–4096 byte bearer value used by the control API>
```

Optionally set `SCORCHKIT_CONSOLE_BIND`; it defaults to `127.0.0.1:7445` and rejects non-loopback
or port-zero values. Run `bash bin/console.sh run`, then open the exact displayed/configured local
origin. The browser never receives the control URL or bearer.

The engagement panel is read-only by design. Target registration and run selectors are restrictions
inside the configured engagement, not authorization to widen it. Project target, job lifecycle, and
finding-triage mutations are sent as exact control API commands after Host, Origin, body, and CSRF
checks.
