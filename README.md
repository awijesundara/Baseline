# Baseline

Agentless fleet inventory and OS/kernel/firmware verification, with a web UI and
an authenticated verification contract for ServiceOps and FlowOps.

## What is implemented

- **Fleet inventory:** add one server, paste/upload CSV, preview validation errors,
  import up to 200 servers atomically, search by name/IP/model/tag, select servers
  with checkboxes, and scan them together.
- **Concurrent collection:** 1–20 Ansible forks or Redfish collector threads per
  run, up to 200 targets. One run executes at a time. Individual errors retain
  successful results from other servers.
- **OS evidence:** Linux OS/kernel, installed/default kernel, kernel-devel,
  DKMS, loaded modules, CPU/hugepage configuration, failed services, time-service
  state, BIOS and NIC information. Windows SSH/PowerShell and Unix/AIX collectors
  provide a smaller OS/hardware inventory. Missing facts stay unknown.
- **Firmware:** a read-only Redfish adapter follows standard system and firmware
  inventory links, independently of the host OS. It reports BIOS, firmware
  component IDs/versions, updateability, and reported component state.
- **Vendor references:** fetch official Red Hat release/kernel tables, Rocky
  release directories, and Dell catalogs; show source URL, retrieval time,
  checksum, candidate applicability, and retrieval errors. CentOS, HPE and IBM
  currently have official reference retrieval, not automated release/catalog
  extraction. Old snapshots remain visible after a failed refresh.
- **Immutable policies and evidence:** exact versions, required/advisory checks,
  revision hashes, persistent reports, JSON downloads, and audit events.
- **Ticket contract:** bind a ServiceOps/FlowOps reference to exact hosts and a
  baseline; only a fresh, complete post-upgrade pass can return `verified: true`.

This is a single-controller development application. Native ServiceOps/FlowOps
buttons, production identity, and remote fleet acceptance are still outstanding.
See [the implementation plan](docs/IMPLEMENTATION_PLAN.md).

## Run locally

Use Python 3.12 on the **controller**:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
export BASELINE_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(24))')"
export BASELINE_ALLOWED_NETWORKS=10.20.0.0/24
export BASELINE_SSH_KEY=/absolute/path/to/read-only-ssh-key
export BASELINE_KNOWN_HOSTS=/absolute/path/to/approved-known-hosts
python -m baseline.server
```

Open **http://127.0.0.1:8090**. Enter the admin token from your local environment.
The UI keeps it in memory only. Serve through an authenticated TLS proxy for
shared access; this preview does not provide production SSO or user accounts.

1. **Host inventory → Add server / Import CSV.** Choose SSH, Redfish, or both.
2. Select servers → **Scan selected**. Start with inventory discovery.
3. Inspect **Firmware inventory** and **Evidence reports**.
4. Refresh **Vendor references**. Review exact model, component, OS branch,
   architecture, entitlement and upgrade dependencies before choosing targets.
5. Create an immutable **Baseline policy** using a starter and approved values.
6. Bind an upgrade ticket and collect again after the upgrade completion boundary.

### CSV format

```csv
name,address,ssh_user,port,protocol,os_family,manufacturer,model,tags,bmc_address,credential_profile
hft-01,10.20.0.11,baseline,22,ssh,linux,Dell,PowerEdge R750,Tokyo,,
hft-02,10.20.0.12,baseline,22,both,linux,HPE,ProLiant DL380 Gen11,Tokyo,10.20.0.112,production-bmc
bmc-03,10.20.0.113,,22,redfish,linux,IBM,REPLACE_EXACT_MODEL,Tokyo,10.20.0.113,production-bmc
```

`name` and `address` are always required. SSH/both requires `ssh_user`.
Redfish/both requires `credential_profile`; the BMC address defaults to the
management address if omitted. CSV imports reject duplicate names and management
IP/port pairs both within the batch and against existing inventory. An invalid
row saves **none** of the batch. Do not include passwords or private keys in CSV.

### Read-only BMC credential profiles

Set `BASELINE_BMC_CREDENTIALS` to a controller-mounted JSON secret file:

```json
{
  "production-bmc": {
    "username": "baseline-reader",
    "password": "REPLACE_IN_SECRET_STORE",
    "ca_file": "/run/secrets/management-ca.pem"
  }
}
```

Only the profile name is stored in inventory. The password is never sent to the
browser or stored in evidence. `ca_file` is optional if the BMC certificate is
already trusted. TLS certificate verification is mandatory, including matching
the configured BMC IP to the certificate SAN. Requests are GET-only and redirects
and foreign-controller links are rejected. Use a read-only BMC account.

### Controller settings

| Variable | Purpose |
|---|---|
| `BASELINE_ADMIN_TOKEN` | Required random token, at least 32 characters. |
| `BASELINE_INTEGRATION_TOKEN` | Optional distinct token; can scan/read, cannot redefine inventory, policy or bindings. |
| `BASELINE_READ_TOKEN` | Optional distinct read-only token. |
| `BASELINE_ALLOWED_NETWORKS` | Explicit management CIDRs; literal IPs only. |
| `BASELINE_SSH_KEY`, `BASELINE_KNOWN_HOSTS` | Controller-side SSH key and approved known-hosts paths. |
| `BASELINE_BMC_CREDENTIALS` | Secret JSON file for named BMC profiles. |
| `BASELINE_ANSIBLE` | Ansible executable, default `ansible-playbook`. |
| `BASELINE_DB` | SQLite path, default `data/baseline.db`. |
| `BASELINE_BIND`, `BASELINE_PORT` | Default `127.0.0.1:8090`. |

Ansible transfers a temporary collector and cleans up its temporary files. It
installs no daemon, modifies no OS configuration and performs no upgrades.
Managed Linux/Unix hosts need a compatible existing Python interpreter and SSH;
Windows needs configured OpenSSH with PowerShell as its default shell. The
controller uses Ansible 2.18 for Windows SSH support. Optional host utilities
(`dkms`, `rpm`, `grubby`, `ethtool`, etc.) must already exist to supply their facts.

## Firmware status and applicability

`bios.version` is read from the system inventory. `firmware.inventory` retains
all returned component metadata. `firmware.versions` contains exact `Id:Version`
strings only for components reporting `Status.State == Enabled`, excluding
Available/Staging/Pending IDs. Missing active-state evidence cannot verify an
installed firmware target. `Updateable` means the BMC says a component can be
updated; it does **not** mean an update is available or needed.

The generic Redfish adapter requires exactly one system per BMC, a standard
UpdateService/FirmwareInventory collection, and no collection pagination.
Multi-node enclosures, legacy HP/iLO interfaces and IBM platform-specific APIs
need adapters. A Redfish endpoint's existence is not a guarantee that all firmware
components are exposed. OS+BMC identity disagreement is a collection error.

Vendor version strings are not universally sortable. Baseline does not assume
that a lexically larger firmware string is newer. Red Hat GA kernels are **not**
current errata kernels. Rocky published directories include historical releases.
Dell candidates include supported models but still require component/OS and
prerequisite review. Exact matching of an approved policy is independent of
vendor-support status. CentOS 7's end-of-life check is explicit in its starter.

## API

All `/api/*` endpoints require a bearer token. JSON writes use the admin token
unless stated otherwise. Mutation requests reject foreign origins.

| Endpoint | Behavior |
|---|---|
| `POST /api/hosts` | Add one host. |
| `POST /api/hosts/import` | `{"csv":"...","preview":true}` or `{"hosts":[...]}`. Omit preview to save. |
| `POST /api/runs` | `{"host_ids":[...],"parallelism":5,"baseline_id":"optional"}`; admin/integration. |
| `POST /api/runs` | `{"binding_id":"...","parallelism":5}` for ticket verification. |
| `GET /api/runs/{id}` | Per-host results and frozen policy/inventory evidence. |
| `GET /api/vendors?model=PowerEdge%20R750` | Sources/candidates; exact Dell model filter, capped at 250 visible candidates per source. |
| `POST /api/vendors/refresh` | `{"source_id":"rhel|rocky|centos|dell|hpe|ibm"}`. |
| `POST /api/baselines` | `{"name":"...","checks":[...],"source_ids":["dell"]}`; optional source IDs freeze successfully retrieved snapshot provenance. |
| `POST /api/bindings` | Bind `external_system`, `ticket_id`, `baseline_id`, `host_ids`, `not_before`, `max_age_seconds`. |
| `GET /api/verification?external_system=serviceops&ticket_id=CHG001` | Current ticket verification. |
| `GET /api/bindings/{id}/verification` | Verification for a particular binding. |

`GET /api/hosts`, `/api/baselines`, `/api/bindings`, `/api/runs`, `/api/audit`,
`/api/catalog`, `/api/templates` provide authenticated lists/metadata.
Standalone discovery reports `collected`, never ticket verification. One busy run
returns HTTP 409 to another start request. The newest ticket-bound attempt
supersedes an older pass. Restart marks interrupted runs as errors.

## Validation and delivery

```sh
python -m unittest discover -s tests -v
python -m pip install playwright
PYTHONPATH=. python tests/browser_fleet.py  # installed Google Chrome
python tools/check_ansible.py              # local controller aliases only
PYTHONPATH=. python tools/refresh_vendor_evidence.py
```

See [validation evidence](docs/VALIDATION.md) and
[vendor retrieval results](docs/vendor-retrieval.json). No production host or BMC
was supplied for this implementation. Supported adapter code and fixture tests
are not live certification of every OS/server model.

## Official references

- [Red Hat releases and shipped kernels](https://access.redhat.com/articles/red-hat-enterprise-linux-release-dates)
- [Rocky release repository](https://download.rockylinux.org/pub/rocky/)
- [CentOS Linux lifecycle](https://www.centos.org/centos-linux/)
- [Dell PowerEdge catalog documentation](https://www.dell.com/support/kbdoc/en-us/000132986/dell-emc-catalog-links-for-poweredge-servers)
- [HPE firmware inventory](https://servermanagementportal.ext.hpe.com/docs/references_and_material/blogposts/firmware_updates/part3/firmware_update_part3)
- [IBM Fix Central](https://www.ibm.com/support/fixcentral/)
- [Ansible Windows SSH requirements](https://docs.ansible.com/projects/ansible/latest/os_guide/windows_ssh.html)
# Baseline
