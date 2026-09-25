# Safehouse manual

Safehouse creates local pentest workspaces. Labs are plain folders; engagements use VeraCrypt containers.

## Install

Install the released package with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install safehouse
safehouse --version
```

Before creating an encrypted engagement on a new host, check that VeraCrypt and ext4 tooling are ready:

```bash
safehouse doctor
```

## Create a Safehouse

Start with a dry run when creating something new:

```bash
safehouse new lab --dry-run "City Council"
safehouse new lab "City Council"

safehouse new engagement --dry-run "Client Safe Name"
safehouse new engagement "Client Safe Name"
```

Labs do not use VeraCrypt. Creating an engagement prompts for a VeraCrypt password and leaves the new Safehouse mounted when creation succeeds.

For one engagement outside the usual location, use a one-time path without changing your saved defaults:

```bash
safehouse new engagement --path "$HOME/client-safehouses" "Client Safe Name"
```

## Work with encrypted engagements

Check the local inventory, then mount or unmount a known engagement:

```bash
safehouse list
safehouse status
safehouse mount "Client Safe Name"
safehouse unmount "Client Safe Name"
safehouse status
```

`list` shows the known inventory. `status` checks the registry against local filesystem and VeraCrypt state. Use the opaque ID, exact display name, or slug as the selector. Safehouse refuses to unmount plain labs.

If a mount is busy, close Obsidian, shells, and file managers using that Safehouse, then retry. Safehouse has no force-unmount option.

## Change defaults

Safehouse works without setup. Its built-in defaults are:

- labs: `~/safehouse/labs`, plain storage
- engagements: `~/safehouse/engagements`, encrypted storage
- encrypted container size: `512M`
- Obsidian profile: `minimal`
- vault layout: `safehouse`

Change defaults with `safehouse defaults set`:

```bash
safehouse defaults show
safehouse defaults set lab --path "$HOME/safehouse-labs" --storage plain
safehouse defaults set engagement --path "$HOME/safehouse-engagements" --storage encrypted
safehouse defaults set engagement --container-size 2G
safehouse defaults set engagement --obsidian-profile work
```

These non-secret settings are stored in `~/.config/safehouse/config.ini`. The `--storage` setting becomes `lab.storage` or `engagement.storage`: `plain` creates a normal folder, while `encrypted` creates a VeraCrypt `.hc` container and mount directory. The built-in policy is plain labs and encrypted engagements.

Remove one saved override, or intentionally reset all overrides:

```bash
safehouse defaults clear lab --path
safehouse defaults clear lab --obsidian-profile
safehouse defaults clear --all
```

## Use a vault layout

The built-in `safehouse` layout is the default. It creates `00_run.md`, `00_access.md`, `README.md`, the numbered work folders, and `_safehouse/templates/`.

It is not compulsory. A vault layout controls the initial files and folders; an Obsidian profile controls editor settings and plugins. To use your own structure, make a deliberately sanitized layout directory, import it as a local snapshot, inspect it, and then choose it as a category default or a one-time creation override:

```bash
safehouse vault-layout import web-notes --from "$HOME/safehouse-layouts/web-notes"
safehouse vault-layout list
safehouse vault-layout show web-notes
safehouse vault-layout verify web-notes

safehouse defaults set lab --vault-layout web-notes
safehouse new lab "Practice Web App"
safehouse new engagement --vault-layout web-notes "Client Placeholder"
```

Imported layouts may have any ordinary file/folder structure. Safehouse copies a custom layout as-is, then adds only a small internal Safehouse marker and the selected Obsidian profile; it does not add the built-in folders, starter notes, `.gitkeep` files, or templates.

Import rejects symlinks, special files, and `.obsidian`, `_safehouse`, `.git`, and `.trash` content. Layout snapshots live under `~/.config/safehouse/vault-layouts/` and are not encrypted merely because a later engagement Safehouse is encrypted. Import only reusable material with no client notes, passwords, tokens, or engagement artifacts.

## Use an Obsidian profile

`minimal` is built in. To reuse settings from another vault, import a profile, then make it the default:

```bash
safehouse obsidian-profile import work --from /path/to/vault
safehouse defaults set engagement --obsidian-profile work
```

Check or update an imported profile:

```bash
safehouse obsidian-profile list
safehouse obsidian-profile verify work
safehouse obsidian-profile replace work --from /path/to/updated-vault
```

To apply a profile to an existing registered Safehouse, mount an encrypted one first and preview the change:

```bash
safehouse obsidian-profile apply --dry-run work --to /path/to/safehouse
safehouse obsidian-profile apply work --yes-replace --to /path/to/safehouse
```

Imported profiles may contain community plugin code. Review it before reuse. Safehouse refuses symlinked profile content and requires an explicit `--yes-replace` before replacing a non-empty `.obsidian` directory.

## Resize an encrypted engagement

Safehouse resizes by copying to a new container. It never resizes a VeraCrypt container in place.

```bash
safehouse resize "Client Safe Name" --to-size 1G --dry-run
safehouse resize "Client Safe Name" --to-size 256M --dry-run
safehouse resize "Client Safe Name" --to-size 1G
safehouse resize "Client Safe Name" --to-size 1G --delete-old
```

The dry run shows current and target size without writing anything. A real resize mounts the source read-only, copies it to a replacement container, verifies paths and file hashes, then switches Safehouse to the verified replacement. It refuses a shrink that cannot safely fit the copied data, ext4 allowance, and safety margin. The old container is retained by default; `--delete-old` explicitly removes it after a successful verified resize.

## Remove a Safehouse

Always inspect the dry run before permanent removal:

```bash
safehouse remove "Old Lab" --dry-run
safehouse remove "Old Lab" --yes

safehouse unmount "Old Client"
safehouse remove "Old Client" --dry-run
safehouse remove "Old Client" --yes
```

Encrypted Safehouses must be closed first. Safehouse refuses mounted, stale, symlinked, or unexpected paths rather than guessing what can be deleted.

## Safety notes

- Safehouse only creates local files and folders.
- It refuses non-empty target folders and unknown/external mount paths.
- There is no `--force`; inspect and move/delete paths manually when needed.
- Use encrypted engagement Safehouses for real engagement material unless ROE says otherwise.
- `00_access.md` can hold access-state material while an encrypted Safehouse is mounted. Do not copy passwords, tokens, hashes, tickets, or similar secrets into chat, reports, reusable notes, or unencrypted exports.
