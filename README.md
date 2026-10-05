# NOVA Kiosk Agent

The Linux device agent for [NOVA Kiosk](https://github.com/novakiosk/novakiosk).
It enrolls kiosks with the control plane, maintains their signed connection,
applies assigned content and runtime settings, and reports observed device and
printer state. It is built for the NOVA Kiosk OS and its coordinated protocol;
it is not a standalone kiosk-management product.

The same executable runs the **Print Bridge** on a central CUPS host. That role
manages printer evidence and fixed queue/job operations without the kiosk's
browser, desktop, or machine-operation lifecycle.

## License

This repository is licensed under the [MIT License](LICENSE)

## Agent 1.1.0 deployment requirements

This source prepares Agent 1.1.0; it does not imply that a release has been
published. Deploy it with a server supporting P-256 enrollment and attended
identity rotation, and the matching OS or Print Bridge packaging that provisions
the dedicated authority account, private state, service units and fixed helpers.
Updating the executable alone does not establish the new account boundary.
Packaging checks `novakiosk-agent capabilities` for `device-authority-v1`;
Agent 1.0.1 does not satisfy that requirement. Existing enrolled devices require
the attended migration and rotation below. Keep the server's explicit legacy
Ed25519 opt-in enabled until those devices have completed rotation.

### Device authority and graphical companion

The OS system service `novakiosk-agentd.service` runs `novakiosk-agent agentd`
as the nonlogin `novakiosk-agent` account. Its identity, enrollment, session
counters and operation journals live in `/var/lib/novakiosk-agentd` (0700).
Without a managed enrollment it waits locally without opening a control-plane
connection. Enrollment automatically becomes active after the attended command
releases the authority lock; no service enable step is needed.

For P-256 identity enrollment, use an attended
administrator terminal using the dedicated account:

```sh
sudo -u novakiosk-agent /usr/bin/novakiosk-agent smoke \
  --state-dir /var/lib/novakiosk-agentd \
  --instance https://YOUR_CONTROL_PLANE --identity-backing auto
```

Fresh auto selection uses TPM when `/dev/tpmrm0` exists, and software only when
it is absent. A present but unavailable TPM fails with an actionable error;
`--identity-backing software` is an explicit choice. Stored backing is always
authoritative. P-256 is enabled by default on the updated server; legacy
Ed25519 remains explicitly gated during transition.

For existing kiosk/Print Bridge state, stop the legacy service and the authority
service, then run `sudo novakiosk-agent migrate-legacy --profile kiosk --instance https://YOUR_CONTROL_PLANE` (or
`print-bridge`). This copies only validated authority files into an empty private
destination and installs a mandatory rotation marker. Complete it as the new
owner with `sudo -u novakiosk-agent novakiosk-agent rotate --identity-backing auto`, then restart the corresponding
authority service. Pending/unapproved enrollment or unresolved operation journals
must be resolved first. Failed/interrupted rotation retains one durable candidate;
retry the same command rather than deleting state or generating a new key.

The daemon exits with status 78 for unavailable/corrupt identity or signing
failures, and systemd does not restart it automatically. Resolve TPM permissions,
hardware or attended recovery before manually restarting; no software fallback
or repeated authorization attempts occur.

The kiosk user service retains its existing unit name but now runs only
`novakiosk-agent runtime`. Chromium, Sway/NOVA Keys application, idle assets and
WayVNC stay under the kiosk account and `/var/lib/novakiosk-runtime`. It connects
to the daemon-owned Unix socket using exact account UID authentication. Bounded
requests name typed operations, desired content and expiring single-use leases;
there is no signing, private-file, executable or relay-token API. Companion
observations are validated before signing and are not hardware attestation.
Printer reconciliation and operation helpers remain separate fixed root units;
only per-user default-printer maintenance crosses to the companion.

Attended identity changes acquire an exclusive state lock. Stop the authority
service before rotation or recovery; an active daemon makes such changes fail
with a busy error. A missing or unsafe identity is never automatically repaired.

## Verification

Run `go vet ./...` and `go test -race ./...` with the Go version in `go.mod`.
The TPM integration tests additionally use `swtpm` and `openssl` from `PATH`;
CI and release checks install the simulator so those cases execute. Local runs
without `swtpm` explicitly skip the simulator cases. The released binary is
static and does not require the simulator or OpenSSL.
