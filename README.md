# Baseline

Agentless OS/kernel/firmware baseline verification for HFT servers, built to
back "verified" evidence on ServiceOps and FlowOps upgrade tickets.

Baseline never installs anything on a managed host. It connects over SSH
with Ansible, runs a single read-only Python script, and evaluates the
result against an immutable, versioned baseline policy. Nothing it collects
is ever used to change a host.

## Why this exists

An OS/firmware upgrade ticket (ServiceOps CHG/CTASK, FlowOps task) says the
work is done. Baseline is the independent evidence that it actually is:
the right kernel is running *and installed as the default boot entry*, the
required DKMS module matches the running kernel, no service is in a failed
state, time sync is healthy, and (for CentOS 7) the host isn't silently
running an end-of-life distribution. A ticket only earns a "Verified" badge
when every required check in the bound baseline revision passes against
*fresh* evidence collected *after* the upgrade completed, from *exactly*
the host set the ticket names.

## Architecture

```
┌───────────────┐    SSH (Ansible)     ┌──────────────┐
│   Baseline    │ ───────────────────▶ │  Managed host │
│   controller  │   runs collect.py,   │  (no agent)   │
│               │   nothing persists   └──────────────┘
└───────┬───────┘
        │ HTTP (Bearer token)
        ▼
┌─────────────────────┐
│ ServiceOps / FlowOps │  GET /api/verification?external_system=...&ticket_id=...
└─────────────────────┘
```

- `baseline/server.py` — a dependency-free `http.server` app (matches the
  zero-framework style of FlowOps) serving both the JSON API and the static
  web UI. Single SQLite file (`baseline/store.py`) holds hosts, baseline
  revisions, ticket bindings, collection runs, and an append-only audit log.
- `baseline/policy.py` — strict, fail-closed evaluation. A field the
  collector couldn't read evaluates as `unknown`, which fails any check
  that requires it. There is no way to "match" an unreadable fact.
- `baseline/runner.py` — builds a throwaway Ansible inventory per run,
  invokes `ansible-playbook` under a process group so a timeout kills SSH
  children too, and collects evidence only through the file the callback
  plugin owns (`ansible/callback_plugins/baseline.py`) — the playbook's
  own stdout is never trusted, and one duplicate host report kills the run.
- `ansible/collect.py` — the one thing that ever runs on a managed host. A
  `/bin/sh` polyglot header picks whatever Python interpreter exists
  (`python3`, RHEL's `platform-python`, `python2`) so CentOS 7 works without
  a pre-provisioned modern Python. Read-only: `/proc`, `/sys`, `/etc/os-release`,
  and read-only invocations of `dkms status`, `rpm -q`, `grubby
  --default-kernel`, `ethtool -i`, `systemctl --failed`, `timedatectl show`.
  Nothing here mutates host state.

## Quick start (local)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install ansible-core   # only the controller needs this; managed hosts need nothing
export BASELINE_ADMIN_TOKEN=$(python3 -c "import secrets;print(secrets.token_hex(24))")
export BASELINE_ALLOWED_NETWORKS=10.0.0.0/8   # comma-separated CIDRs of your management VLAN
python3 -m baseline.server
```

Open `http://127.0.0.1:8090`, sign in with the admin token, register a host,
create a baseline (see `examples/*.json` for CentOS 7 / Rocky 8 / 9 / 10
starters — every starter fails by design until you replace its
`REPLACE_*` placeholders with your approved kernel/DKMS/firmware versions),
bind it to a ticket, and run a verification.

Run the tests: `python3 -m unittest discover -s tests -v` (20 tests, no
network or real SSH required — the Ansible invocation is mocked at the
`subprocess.Popen` boundary in the collection tests).

## Configuration

| Variable | Purpose |
|---|---|
| `BASELINE_ADMIN_TOKEN` | Required, ≥32 chars. Full read/write access. |
| `BASELINE_INTEGRATION_TOKEN` | Optional, ≥32 chars. Can start collection runs and read everything; cannot create hosts/baselines/bindings. Give this one to ServiceOps/FlowOps. |
| `BASELINE_READ_TOKEN` | Optional, ≥32 chars. Read-only. |
| `BASELINE_ALLOWED_NETWORKS` | Comma-separated CIDRs. A host address outside every listed range, or loopback/link-local/multicast, is rejected at creation and re-checked at run time. |
| `BASELINE_SSH_KEY` / `BASELINE_KNOWN_HOSTS` | Paths used for every collection run. Host key checking is always on (`StrictHostKeyChecking=yes`); there is no way to disable it. |
| `BASELINE_ANSIBLE` | `ansible-playbook` binary path (default: resolved from `PATH`). |
| `BASELINE_DB` | SQLite path (default `data/baseline.db`). |
| `BASELINE_BIND` / `BASELINE_PORT` | Listen address (default `127.0.0.1:8090`). |

Three role tokens, not one: the *admin* role manages inventory and
baselines; the *integration* role (meant for ServiceOps/FlowOps to hold) can
only trigger runs and read results — it can never redefine what "verified"
means; the *reader* role is read-only for dashboards/audits.

## API (for ServiceOps/FlowOps integration)

All endpoints require `Authorization: Bearer <token>`. All mutating
endpoints require the admin token except `POST /api/runs`, which the
integration token may also call.

- `GET /api/verification?external_system=serviceops&ticket_id=CHG0012345`
  — the integration endpoint. Looks up the most recent binding for that
  ticket and returns its verification result. Response shape:
  ```json
  {"verified": true, "status": "verified", "binding_id": "...",
   "external_system": "serviceops", "ticket_id": "CHG0012345",
   "run_id": "...", "evidence_sha256": "...", "completed_at": 1234567890}
  ```
  `status` is one of `not_bound`, `not_run`, `queued`, `running`, `error`,
  `fail`, `expired` (a pass that's gone stale or off-target), or `verified`.
  Only `verified: true` should ever unlock a "Verified" ticket action.
- `POST /api/bindings` (admin) — bind a ticket to an exact host set and
  baseline revision before work starts. Body: `{"external_system":
  "serviceops"|"flowops", "ticket_id": "...", "baseline_id": "...",
  "host_ids": [...], "max_age_seconds": 3600, "not_before": <unix ts>}`.
  `not_before` should be the upgrade's planned/actual completion time —
  evidence collected before it can never verify the binding.
- `POST /api/runs` (admin or integration) — `{"binding_id": "..."}`. Queues
  a collection; only one run executes at a time system-wide. Poll
  `GET /api/runs/{id}` or just re-poll the verification endpoint above.
- `GET /api/hosts`, `GET /api/baselines`, `GET /api/bindings`, `GET
  /api/runs`, `GET /api/audit`, `GET /api/catalog`, `GET /api/templates` —
  inventory and metadata, any role.

### What "verified" actually requires

`verification()` in `baseline/server.py` — every one of these, checked
server-side, not something a caller can weaken:

1. The **newest** run for that binding has `status == "pass"` (an older
   pass is superseded by any newer attempt, pass or fail — you cannot point
   at a stale success once a re-run has happened).
2. It was collected against **exactly** the bound host set and baseline
   revision (`revision_sha256`-addressed; editing a baseline creates a new
   revision, it never mutates one in place).
3. `run.started_at >= binding.not_before` — no pre-upgrade evidence.
4. `now - run.completed_at <= binding.max_age_seconds` — no stale evidence.

## Wiring a "Verified" button into ServiceOps or FlowOps

Neither integration is built yet — this is the contract to build against:

1. Add an admin-configurable Baseline connection (base URL + the
   integration-role bearer token), stored the same way ServiceOps already
   stores its NetBox/webhook credentials.
2. When a CHG/CTASK (ServiceOps) or upgrade task (FlowOps) is created for
   an OS/firmware change, call `POST /api/bindings` on Baseline with the
   ticket's external system + ID, the affected hosts, and the approved
   baseline revision — ideally right when the change is approved, so
   `not_before` can be set to the planned implementation window.
3. On the ticket detail view, poll `GET /api/verification` (SSRF-hardened
   the same way ServiceOps's NetBox proxy is — exact host/port match
   against the configured base URL, no redirects followed). Render the
   `status` value as a badge. Only offer a "Mark verified" ticket action
   when `verified: true`.
4. After the implementer runs the actual upgrade, either they or an
   automation step calls `POST /api/runs` on Baseline; the ticket badge
   updates on next poll.

## Security posture

- Read-only by construction on every managed host — no daemon installed,
  no writable file transferred, nothing in `ansible/collect.py` executes a
  command that isn't itself read-only.
- SSH host key checking is mandatory (`StrictHostKeyChecking=yes`); there
  is no configuration path that disables it.
- Management addresses are restricted to explicit CIDRs
  (`BASELINE_ALLOWED_NETWORKS`) and loopback/link-local/multicast/
  unspecified are always rejected, both when a host is registered and
  again at run time (defense against a later config change silently
  widening scope).
- Baseline revisions are immutable and content-addressed
  (`revision_sha256`); a ticket binding freezes the exact revision and
  host set, so neither can be silently swapped after the fact.
- Evidence itself is fail-closed: a field the collector couldn't read is
  `unknown`, never treated as a pass.
- Secrets (role tokens) are stripped from the environment before Ansible
  ever runs, and compared with `hmac.compare_digest`.
- CSRF-relevant: mutating requests require `Content-Type: application/json`
  and are rejected if `Origin` doesn't match `Host`.

## Known gaps / next steps

- ServiceOps and FlowOps integration (the actual "Verified" button) is not
  implemented yet — see the contract above.
- No systemd unit / container image yet; run as a supervised process
  (`ExecStart=... python3 -m baseline.server`) behind the same reverse
  proxy pattern used for ServiceOps/FlowOps.
- No TLS termination built in — deploy behind a TLS-terminating proxy, same
  as FlowOps.
- Firmware/BIOS version checks exist as fields (`bios.version`,
  `bios.date`) but there's no vendor-firmware-catalog cross-check yet;
  today you pin an exact expected string per baseline.
