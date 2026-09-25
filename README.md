# Safehouse

Safehouse is a local-first CLI for clean pentest labs and VeraCrypt-backed engagement workspaces. It creates a consistent folder scaffold and keeps the normal encrypted workflow deliberately boring: check, mount, work, unmount, check.

Status: alpha. Review its output before relying on it for client work.

## Install

Install the released package with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install safehouse
safehouse --version
safehouse doctor
```

Encrypted engagements require VeraCrypt and `e2fsprogs` (`mkfs.ext4`). `safehouse doctor` checks both before you create one. Labs do not need VeraCrypt.

## Quick start

Labs are plain local folders and do not require VeraCrypt:

```bash
safehouse new lab --dry-run "PortSwigger SQLi"
safehouse new lab "PortSwigger SQLi"
```

Engagements default to encrypted VeraCrypt containers. Run `doctor` first on a new host, then preview before creating anything:

```bash
safehouse doctor
safehouse new engagement --dry-run "ACME External"
safehouse new engagement "ACME External"
```

Daily engagement lifecycle:

```bash
safehouse status
safehouse mount "ACME External"
# work in the displayed mount path
safehouse unmount "ACME External"
safehouse status
```

## Vault layouts

`safehouse` is the built-in default layout. It creates this starting tree:

```text
00_run.md        00_access.md      README.md
01_scans/        02_notes/         03_leads/
04_primitives/   05_findings/      08_reports/
99_archive/      _safehouse/templates/
```

That is a default, not a requirement. A vault layout controls files and folders; an Obsidian profile controls editor settings and plugins. Import a sanitized reusable layout, then set it once per category or select it for one Safehouse:

```bash
safehouse vault-layout import web-notes --from "$HOME/safehouse-layouts/web-notes"
safehouse vault-layout verify web-notes
safehouse defaults set lab --vault-layout web-notes
safehouse new engagement --vault-layout web-notes "Client Placeholder"
```

Safehouse copies imported layouts into its local host-side store before use. Keep those source layouts free of client notes, credentials, and engagement artifacts; encryption for a later engagement does not encrypt the stored layout snapshot.

## Safety model

- Password entry requires an interactive terminal. Safehouse never accepts it in argv, environment variables, config, state, or logs.
- `remove` is dry-run first and needs `--yes`. Mounted Safehouses and unexpected artifacts are refused.
- `resize` creates and verifies a replacement container; it never resizes a container in place.
- A closed container protects its contents, not host-side slugs, paths, state metadata, imported-profile source paths, or files while mounted.

## Support

If Safehouse has been useful to you, you can support continued development through GitHub Sponsors or Ko-fi.

Bug reports, supported-host test results, and documentation corrections are useful too. Keep issues free of client data, passwords, container contents, and engagement artifacts.

See [the manual](docs/manual.md) for defaults, Obsidian profiles, resizing, removal, and safety guidance. Safehouse is licensed under the MIT License; see [LICENSE](LICENSE).

Source contributors: see [CONTRIBUTING.md](CONTRIBUTING.md).
