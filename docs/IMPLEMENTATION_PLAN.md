# Baseline implementation plan

## Ownership and verification contract

ServiceOps owns ITSM approval, CI scope and ticket lifecycle. FlowOps owns runbook
execution and dependency gates. Baseline owns technical policy evaluation and
collection evidence. None of these responsibilities should be silently delegated
to a vendor's definition of "latest".

Verification freezes the approved policy revision and affected host set, requires
post-upgrade collection, and expires with the configured lifetime. A missing,
unreachable, unsupported or mismatching required check fails closed. A report
hash detects accidental differences; it is not a hardware attestation or an
external signature protecting against a compromised controller/managed host.

## Phase 1: Fleet and collection foundation — implemented, lab acceptance pending

- Single-host and atomic CSV/JSON bulk inventory, searchable selection, 200 hosts.
- Configurable 1–20 server concurrency, separate host results and failure handling.
- Linux collector; narrower Windows/Unix/AIX collectors; standard Redfish adapter.
- Immutable baselines, ticket bindings, evidence download, scoped bearer access.
- OS/kernel/DKMS/hardware starter policies, including CentOS 7 and Rocky 8/9/10.
- Real browser and API regression evidence; production systems not yet supplied.

## Phase 2: Vendor intelligence — implemented core, partial vendor coverage

- Live Red Hat release-table, Rocky directory, Dell XML catalog parsing.
- Official-source allowlist, retrieval timestamps and hashes, stale/error states.
- Exact Dell model filtering with PowerEdge prefix normalization.
- CentOS/HPE/IBM official reference retrieval; HPE and IBM structured firmware
  catalog import and entitlement-backed adapters remain to implement.
- Vendor snapshot provenance can be attached to a new immutable policy.
- Next: extract package/architecture/component identifiers and dependency rules;
  compare exact installed components against applicable candidates; pull RPM
  metadata/advisories for approved repositories/EUS streams. Add governed
  candidate-to-approved-policy review in the UI. Do not make latest-version
  claims from release directories or GA kernel tables.

## Phase 2.5: Ansible-executed OS upgrades with automatic rollback — implemented (Linux dnf/yum), lab acceptance pending

- A job is a plan/apply pipeline, not a one-shot action: `POST /api/jobs` runs
  a read-only dry run (`dnf check-update` via `ansible/plan.py`) against every
  host and stops at `planned`/`no_changes`. Nothing on any host changes until
  an admin calls `POST /api/jobs/{id}/confirm`.
- Confirmed jobs run in host batches (`batch_size`, default = all hosts as one
  batch). Each batch: collect pre-upgrade evidence (reuses the existing,
  unmodified `ssh_collect`/`verify.yml`) → `dnf upgrade` the exact package set
  named by the dry run, never an unbounded upgrade → reboot and wait if a
  kernel package changed → re-collect and evaluate against the job's bound
  baseline.
- A batch whose post-upgrade check fails **automatically rolls back**:
  `dnf history undo <captured transaction id>`, restore the previous default
  kernel via `grubby --set-default`, reboot, and re-verify against the
  pre-upgrade facts. Rollback success ends the batch `rolled_back`; rollback
  failure ends it `rollback_failed` and is never retried or hidden — it halts
  the job and requires a human to look at the host directly. A failing batch
  always stops any remaining batches.
- A job is gated the same way as a collection run: only one active job
  (`planning`/`running_plan`/`queued`/`running`) at a time, fleet-wide; an
  optional `not_before` maintenance-window start; `cancel` is only allowed
  before or between batches, never mid-remote-command; every stage transition
  is audited (`job.planned`, `job.upgrade_started`, `job.batch_upgraded`,
  `job.rollback_started`, `job.rolled_back`, `job.rollback_failed`,
  `job.completed`).
- Real Ansible/callback plumbing verified end-to-end on the controller
  platform via `tools/check_upgrade_ansible.py` (local-connection aliases,
  same approach `tools/check_ansible.py` already uses for `verify.yml`); API
  contract and the full plan/batch/rollback state machine covered by
  `tests/test_upgrade.py` (patched Ansible subprocess, real HTTP + SQLite,
  same style as `tests/test_baseline.py`); UI wiring covered by
  `tests/browser_upgrade.py`.
- **Explicit scope for this phase, not silently dropped**: Windows, apt
  (Debian/Ubuntu), and AIX/Unix execution are not implemented — only Linux
  dnf/yum hosts are upgraded; `plan.yml`/`upgrade.yml`/`rollback.yml` no-op
  for non-Linux hosts today. No filesystem/LVM snapshotting — rollback is
  package/kernel-transaction level only, and depends on the old package
  builds still being available to `dnf` (repo or local cache), the same
  real-world limitation `dnf history undo` always has. No network-device
  firmware upgrade. No cross-job concurrency. No canary-by-percentage
  (batch *size* is supported; an automatic canary policy is not). Real
  end-to-end execution against an actual Rocky/RHEL lab host is pending —
  needs a real target, exactly like Phase 1's own "lab acceptance pending."

## Phase 3: Native ServiceOps and FlowOps integration — pending

1. Add named, encrypted server-side connection settings in each application.
2. Store explicit CI-to-Baseline host mappings; validate affected CI coverage.
3. Admin-controlled binding creation fixes the approved policy and host set.
   Integration tokens intentionally cannot create/redefine bindings.
4. On upgrade completion, queue the bound verification using an integration token.
5. Render a native Verified/evidence button using current authenticated status.
   Recheck evidence at the authoritative transition, not only in the browser.
6. Preserve ticket history, expiry/reverification and existing workflow approvals.
7. Add real end-to-end regressions and deploy each changed application using its
   repository's established delivery contract.

## Phase 4: Production controller — pending

- Named users, SSO, organizational isolation, per-user audit identities, credential
  rotation and a secret-manager integration. Current roles use shared tokens.
- Durable distributed job leases, cancellation, schedules, progress per host,
  policy assignment per hardware/OS group and retention controls.
- Add legacy/non-Redfish vendor adapters and machine-specific compatibility
  matrices; validate real Dell/HPE/IBM models and target OS releases.
- Validate HFT-specific PTP offset, NIC offloads/rings/queues, IRQ affinity,
  NUMA placement, tuned profiles, IOMMU, microcode and reboot requirements with
  site-approved thresholds. Current service-state checks do not prove latency.
- Build and inspect an immutable image, deploy with persistent storage and a
  protected endpoint, validate restore/restart, health/readiness and audit logs.

## Support statement

The inventory accepts arbitrary manufacturer/model labels. Standard Redfish
firmware collection is independent of the host OS. The current collector matrix
is not universal support: ESXi without Python, legacy iLO, multi-node BMCs,
paginated firmware inventory, IBM HMC/ASMI and other platforms need adapters and
live acceptance. Unknown capabilities are not compliance passes.
