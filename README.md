# Safehouse

Safehouse is a local-first CLI that creates a structured Safehouse scaffold for pentest labs and manages VeraCrypt-backed engagement Safehouses. Its encrypted lifecycle is check, mount, work, unmount, check.

Status: alpha. Review its output before relying on it for client work.

## Install

Install the released package with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install safehouse
safehouse --version
safehouse doctor
```

Encrypted Safehouses require VeraCrypt and `e2fsprogs` (`mkfs.ext4`). `safehouse doctor` checks both before you create one. Labs use plain storage by default and do not need VeraCrypt.

## Quick start

Labs use plain local folders by default and do not require VeraCrypt:

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
