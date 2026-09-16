# Baseline

Agentless Linux fleet inventory and OS/kernel baseline verification, with a
web UI and an authenticated verification contract for ServiceOps and FlowOps.

## What is implemented

- **Fleet inventory:** add management hosts (name, IP, SSH user/port, tags)
  and select them for a scan.
- **Collection:** a read-only Ansible playbook connects over SSH (strict host
  key checking, no daemon installed, no OS changes) and snapshots OS/kernel
  facts. One collection run executes at a time; an unreachable host still
  leaves other hosts' results intact.
- **OS evidence:** Linux OS/kernel, installed/default kernel, kernel-devel,
  DKMS, loaded modules, CPU/hugepage configuration, failed services,
  time-service state, BIOS version/date, and NIC driver/firmware/link state.
  Missing facts stay unknown rather than assumed.
- **Immutable policies and evidence:** exact versions, required/advisory
  checks, revision hashes, persistent per-run reports, JSON downloads, and an
  audit log.
- **Ticket contract:** bind a ServiceOps/FlowOps reference to exact hosts and
  a baseline revision; only a fresh, complete post-upgrade pass can return
  `verified: true`.
- **Accounts:** username/password sign-in with server-side sessions;
  administrators create/revoke/reset additional admin or read-only accounts.
  A separate bearer token is available for machine callers (e.g.
  ServiceOps/FlowOps) that only need to read state and trigger runs.

This is a single-controller preview: one Ansible collector, one SQLite
database, no BMC/firmware collection, no Windows/Unix collectors, no vendor
catalog lookups, and no CSV import. Native ServiceOps/FlowOps buttons,
production SSO, and remote fleet acceptance are still outstanding.

## Run locally

Use Python 3.12 on the **controller**:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
export BASELINE_ADMIN_USERNAME=admin
export BASELINE_ADMIN_PASSWORD="choose a passphrase of at least 12 characters"
export BASELINE_ALLOWED_NETWORKS=10.20.0.0/24
export BASELINE_SSH_KEY=/absolute/path/to/read-only-ssh-key
export BASELINE_KNOWN_HOSTS=/absolute/path/to/approved-known-hosts
python -m baseline.server
```

Open **http://127.0.0.1:8090**. Sign in with the administrator username/password
from your local environment. The browser session is a server-side, HttpOnly,
SameSite=Strict cookie good for 24 hours; use **Disconnect** to end it early.
Serve through an authenticated TLS proxy for shared access; this preview does
not provide production SSO.

1. **Host inventory → Add host.** Register a management IP inside
   `BASELINE_ALLOWED_NETWORKS`.
2. Select hosts → **Scan selected**.
3. Create an immutable **Baseline policy**, optionally starting from one of
   the distribution starters in `examples/`.
4. Bind an upgrade ticket to exact hosts and a baseline, then run
   verification again after the upgrade's completion boundary.
5. **Access** (admin only): create additional accounts, reset a password, or
   revoke access.

### Controller settings

| Variable | Purpose |
|---|---|
| `BASELINE_ADMIN_USERNAME` | Required bootstrap admin username (lowercase letters/digits/._- , 3-32 chars). Only used the first time the database has no accounts yet. |
| `BASELINE_ADMIN_PASSWORD` | Required bootstrap admin password, at least 12 characters. Only used for that same first-run bootstrap. |
| `BASELINE_INTEGRATION_TOKEN` | Optional bearer token for ServiceOps/FlowOps machine calls; can scan/read, cannot redefine inventory, policy or bindings. |
| `BASELINE_ALLOWED_NETWORKS` | Explicit management CIDRs; literal IPs only. |
| `BASELINE_SSH_KEY` | Controller-side SSH private key path. |
| `BASELINE_SSH_CERT` | Optional certificate file matching `BASELINE_SSH_KEY`, for CA-issued short-lived SSH certificates (e.g. a FreeIPA OpenSSH CA). |
| `BASELINE_KNOWN_HOSTS` | Static known_hosts file path. Default host-key trust mode; mutually exclusive with `BASELINE_KNOWN_HOSTS_COMMAND`. |
| `BASELINE_KNOWN_HOSTS_COMMAND` | OpenSSH `KnownHostsCommand` instead of a static file, for centrally managed host keys (e.g. FreeIPA/SSSD's `sss_ssh_knownhostsproxy`). |
| `BASELINE_ANSIBLE` | Ansible executable, default `ansible-playbook`. |
| `BASELINE_DB` | SQLite path, default `data/baseline.db`. |
| `BASELINE_BIND`, `BASELINE_PORT` | Default `127.0.0.1:8090`. |

Ansible transfers a temporary collector and cleans up its temporary files. It
installs no daemon, modifies no OS configuration and performs no upgrades.
Managed hosts need a compatible existing Python interpreter and SSH. Optional
host utilities (`dkms`, `rpm`, `grubby`, `ethtool`, etc.) must already exist
to supply their facts; missing ones just leave that fact unknown.

## API

All `/api/*` endpoints require either a signed-in session cookie (browser
users, via `POST /api/login` with `{"username":...,"password":...}`) or the
`BASELINE_INTEGRATION_TOKEN` bearer token (machine callers such as
ServiceOps/FlowOps). JSON writes use an administrator account unless stated
otherwise. An administrator creates additional admin/reader accounts with
`POST /api/users`. Mutation requests reject foreign origins.

| Endpoint | Behavior |
|---|---|
| `POST /api/login` | `{"username":...,"password":...}`; sets the session cookie. No prior auth needed. |
| `POST /api/logout` | Ends the current session. |
| `POST /api/users` | `{"username":...,"password":...,"role":"admin"|"reader"}`; admin only. |
| `GET /api/users` | List accounts (username/role only); admin only. |
| `POST /api/users/{username}/revoke` | Delete an account and sign out its sessions; admin only, refuses to remove the last admin. |
| `POST /api/users/{username}/reset` | `{"password":...}`; sets a new password and signs out its sessions; admin only. |
| `POST /api/hosts` | Add one host. |
| `POST /api/runs` | `{"binding_id":"..."}`; starts collection for a bound ticket; admin/integration. |
| `GET /api/runs/{id}` | Per-host results and frozen policy/inventory evidence. |
| `POST /api/baselines` | `{"name":"...","checks":[...]}`; admin only. |
| `POST /api/bindings` | Bind `external_system`, `ticket_id`, `baseline_id`, `host_ids`, `not_before`, `max_age_seconds`; admin only. |
| `GET /api/verification?external_system=serviceops&ticket_id=CHG001` | Current ticket verification. |
| `GET /api/bindings/{id}/verification` | Verification for a particular binding. |

`GET /api/hosts`, `/api/baselines`, `/api/bindings`, `/api/runs`, `/api/audit`,
`/api/catalog`, `/api/templates` provide authenticated lists/metadata.
Standalone discovery reports `collected`, never ticket verification. One busy run
returns HTTP 409 to another start request. The newest ticket-bound attempt
supersedes an older pass. Restart marks interrupted runs as errors.

## Validation

```sh
python -m unittest discover -s tests -v
```

No production host was supplied for this implementation; the test suite
covers the API, policy evaluation, and the SSH collection path, not live
certification against every OS/server model.
