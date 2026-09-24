#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import stat
import os
import json
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
HAS_PRIVATE_RELEASE_TOOLING = (ROOT / 'scripts' / 'build-public-candidate').is_file()
sys.path.insert(0, str(ROOT))

import safehouse


class SafehouseTests(unittest.TestCase):
    def run_cli_with_home(
        self,
        home: Path,
        *args: str,
        input_text: str | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env['SAFEHOUSE_HOME'] = str(home)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [sys.executable, str(ROOT / 'safehouse.py'), *args],
            cwd=ROOT,
            env=env,
            check=False,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def run_tty_cli_with_home(
        self,
        home: Path,
        *args: str,
        password_values: list[str],
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {'SAFEHOUSE_HOME': str(home)}
        if extra_env:
            env.update(extra_env)
        stdout = io.StringIO()
        stderr = io.StringIO()
        values = iter(password_values)
        with mock.patch.dict(os.environ, env, clear=False), \
            mock.patch('safehouse.sys.stdin.isatty', return_value=True), \
            mock.patch('safehouse.getpass.getpass', side_effect=lambda prompt: next(values)), \
            mock.patch('builtins.input', return_value=''), \
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                returncode = safehouse.main(list(args))
            except SystemExit as exc:
                returncode = cast(int, exc.code)
        return subprocess.CompletedProcess(list(args), returncode, stdout.getvalue(), stderr.getvalue())

    def test_slug_rejects_path_traversal_and_control_names(self) -> None:
        bad_names = ['', '   ', '.', '..', '../client', 'client/name', 'client\x00name', 'client\nname']

        for name in bad_names:
            with self.subTest(name=repr(name)):
                with self.assertRaises(ValueError):
                    safehouse.slug_name(name)

    def test_slug_is_strict_lowercase_hyphen_identifier(self) -> None:
        self.assertEqual(safehouse.slug_name('Client Safe Name'), 'client-safe-name')
        self.assertEqual(safehouse.slug_name('Bad_Client: Name'), 'bad-client-name')

    def test_safehouse_id_is_opaque_and_uses_hc_extension(self) -> None:
        safehouse_id = safehouse.new_safehouse_id(lambda n: b'\x7f:\x9c!')

        self.assertEqual(safehouse_id, 'sh-7f3a9c21')
        self.assertEqual(safehouse.container_filename(safehouse_id), 'sh-7f3a9c21.hc')

    def test_derived_paths_use_per_safehouse_container_and_mount_tree(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            roots = safehouse.SafehouseRoots(
                container_dir=Path(td) / 'containers',
                mount_dir=Path(td) / 'mounts',
            )

            paths = safehouse.derive_safehouse_paths(roots, 'Client Safe Name', safehouse_id='sh-7f3a9c21')

            self.assertEqual(paths.display_name, 'Client Safe Name')
            self.assertEqual(paths.slug, 'client-safe-name')
            self.assertEqual(paths.safehouse_id, 'sh-7f3a9c21')
            self.assertEqual(paths.container_path, Path(td) / 'containers' / 'client-safe-name' / 'sh-7f3a9c21.hc')
            self.assertEqual(paths.mount_path, Path(td) / 'containers' / 'client-safe-name' / 'mount')

    def test_create_lab_safehouse_scaffold(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = safehouse.create_safehouse_scaffold('lab', 'City Council', td)
            self.assertTrue((root / '00_run.md').is_file())
            self.assertTrue((root / '00_access.md').is_file())
            for folder in safehouse.FOLDERS:
                self.assertTrue((root / folder).is_dir(), folder)
            run = (root / '00_run.md').read_text(encoding='utf-8')
            access = (root / '00_access.md').read_text(encoding='utf-8')
            self.assertIn('## Current State', run)
            self.assertIn('# Log', run)
            self.assertNotIn('## Key Links', run)
            self.assertNotIn('Access ledger: [[00_access]]', run)
            self.assertIn('HH:mm — action summary', run)
            self.assertIn('Evidence:', run)
            self.assertIn('Refs:', run)
            self.assertIn('credentials, hashes, tokens, tickets, sessions, and loot references may live here directly', access)
            self.assertIn('| Username / Principal | Secret / Hash / Token              | Realm / Host            | Type                                                  | Source / Evidence      | Validated On                                        | Access / Privilege | Notes                     | Status |', access)
            self.assertNotIn('Unlocks', access)

    def test_create_engagement_mentions_veracrypt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = safehouse.create_safehouse_scaffold('engagement', 'Client Safe', td)
            readme = (root / 'README.md').read_text(encoding='utf-8')
            access = (root / '00_access.md').read_text(encoding='utf-8')
            self.assertIn('VeraCrypt', readme)
            self.assertIn('Plaintext secrets may live here only while this encrypted Safehouse is mounted', access)

    def test_safehouse_scaffold_helpers_reject_legacy_note_preconfiguration_args(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(TypeError):
                safehouse.create_safehouse_scaffold('lab', 'City Council', td, platform='Hack Smarter')
            with self.assertRaises(TypeError):
                safehouse.scaffold_safehouse_root(Path(td) / 'legacy', 'lab', 'City Council', platform='Hack Smarter')
            with self.assertRaises(TypeError):
                safehouse.scaffold_safehouse_root(Path(td) / 'legacy-real', 'lab', 'City Council', real_engagement=True)

    def test_generated_safehouse_has_exact_stage_one_folder_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = safehouse.create_safehouse_scaffold('lab', 'City Council', td)

            folders = sorted(path.name for path in root.iterdir() if path.is_dir())

            self.assertEqual(folders, sorted([*safehouse.FOLDERS, '_safehouse']))
            self.assertNotIn('06_evidence', folders)
            self.assertNotIn('07_loot', folders)
            for folder in safehouse.FOLDERS:
                self.assertTrue((root / folder / '.gitkeep').is_file(), folder)
                self.assertFalse((root / folder / '_README.md').exists(), folder)

    def test_generated_safehouse_includes_log_entry_templates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = safehouse.create_safehouse_scaffold('engagement', 'Client Safe', td)

            lab_template = root / '_safehouse' / 'templates' / 'lab-log-entry.md'
            engagement_template = root / '_safehouse' / 'templates' / 'engagement-log-entry.md'

            self.assertTrue(lab_template.is_file())
            self.assertTrue(engagement_template.is_file())
            self.assertFalse((root / '02_notes' / 'templates').exists())
            self.assertIn('HH:mm — action summary', lab_template.read_text(encoding='utf-8'))
            self.assertIn('YYYY-MM-DD HH:mm TZ — action summary', engagement_template.read_text(encoding='utf-8'))
            self.assertNotIn('secret', lab_template.read_text(encoding='utf-8').lower())
            self.assertNotIn('secret', engagement_template.read_text(encoding='utf-8').lower())

    def test_minimal_obsidian_profile_points_templates_to_safehouse_metadata_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            root = Path(td) / 'safehouse-root'

            applied = safehouse.apply_obsidian_profile(paths, 'minimal', str(root))
            templates = json.loads((applied / 'templates.json').read_text(encoding='utf-8'))

            self.assertEqual(templates['folder'], '_safehouse/templates')

    def test_generated_run_note_avoids_legacy_platform_preconfiguration(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = safehouse.create_safehouse_scaffold('lab', 'City Council', td)

            run = (root / '00_run.md').read_text(encoding='utf-8')

            self.assertIn('category: lab', run)
            self.assertNotIn('safehouse_category:', run)
            self.assertNotIn('**Safehouse category:**', run)
            self.assertNotIn('**Category:**', run)
            self.assertNotIn('workspace_type:', run)
            self.assertNotIn('**Workspace type:**', run)
            self.assertIn('## Current State', run)
            self.assertIn('## Scope', run)
            self.assertNotIn('platform:', run)
            self.assertNotIn('event:', run)
            self.assertNotIn('**Platform/Event:**', run)
            self.assertNotIn('<', run)
            self.assertNotIn('>', run)

    def test_generated_run_note_uses_single_operator_placeholder_instead_of_templates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = safehouse.scaffold_safehouse_root(Path(td) / 'web-lab', 'lab', 'Web Lab')

            run = (root / '00_run.md').read_text(encoding='utf-8')

            self.assertNotIn('template:', run)
            self.assertIn('# Log', run)
            self.assertIn('HH:mm — action summary', run)
            self.assertIn('Cleanup needed: none known yet', run)
            self.assertNotIn('# Handoff', run)
            self.assertNotIn('## Focus / Method Notes', run)
            self.assertNotIn('Findings / Report Seeds', run)
            self.assertNotIn('# Web Application', run)
            self.assertNotIn('# API Testing', run)
            self.assertNotIn('# Active Directory', run)
            self.assertNotIn('platform:', run)

    def test_new_rejects_removed_template_option(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_dir = Path(td) / 'labs'
            set_result = self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--path', str(lab_dir))

            result = self.run_cli_with_home(home, 'new', 'lab', 'API Lab', '--template', 'api')

            self.assertEqual(set_result.returncode, 0, set_result.stderr)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('unrecognized arguments: --template', result.stderr)
            self.assertFalse((lab_dir / 'api-lab').exists())

    def test_generated_engagement_notes_have_stricter_secret_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = safehouse.create_safehouse_scaffold('engagement', 'Client Safe', td)

            run = (root / '00_run.md').read_text(encoding='utf-8')
            access = (root / '00_access.md').read_text(encoding='utf-8')
            readme = (root / 'README.md').read_text(encoding='utf-8')

            self.assertNotIn('safehouse_category:', run)
            self.assertNotIn('**Safehouse category:**', run)
            self.assertNotIn('workspace_type:', run)
            self.assertNotIn('**Workspace type:**', run)
            self.assertIn('Close it when not in use', readme)
            self.assertIn('Plaintext secrets may live here only while this encrypted Safehouse is mounted', access)
            self.assertIn('| Username / Principal | Secret / Hash / Token              | Realm / Host            | Type                                                  | Source / Evidence      | Validated On                                        | Access / Privilege | Notes                     | Status |', access)
            self.assertIn('| user                 | password / hash / token or ref     | domain / host / app     | password / hash / ticket / cert / session / account   |', access)
            self.assertIn('caveat / next use', access)
            self.assertNotIn('<', access)
            self.assertNotIn('>', access)
            self.assertNotIn('Unlocks', access)


    def test_refuses_non_empty_target_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'existing'
            root.mkdir()
            (root / 'keep.txt').write_text('do not overwrite', encoding='utf-8')
            with self.assertRaises(SystemExit):
                safehouse.create_safehouse_scaffold('lab', 'Existing', td)

    def test_scaffold_allows_native_ext4_lost_found_mount_marker(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'mounted-root'
            lost_found = root / 'lost+found'
            lost_found.mkdir(parents=True)

            created = safehouse.scaffold_safehouse_root(root, 'engagement', 'Native Smoke')

            self.assertEqual(created, root)
            self.assertTrue(lost_found.is_dir())
            self.assertTrue((root / '00_run.md').is_file())

    def test_scaffold_refuses_fake_lost_found_file_marker(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'mounted-root'
            root.mkdir()
            (root / 'lost+found').write_text('not a directory\n', encoding='utf-8')

            with self.assertRaises(SystemExit):
                safehouse.scaffold_safehouse_root(root, 'engagement', 'Native Smoke')

    def test_force_flag_is_rejected_by_parser(self) -> None:
        parser = safehouse.build_parser()

        with self.assertRaises(SystemExit):
            parser.parse_args(['new', 'lab', 'City Council', '--force'])

    def test_top_level_help_is_operator_grade(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / 'safehouse.py'), '--help'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('personal local operator tool', result.stdout)
        self.assertIn('Config/state: ~/.config/safehouse/', result.stdout)
        self.assertIn('No passwords in argv, env, config, state, or logs.', result.stdout)
        self.assertIn('Examples:', result.stdout)
        self.assertIn('safehouse defaults set lab --path "$HOME/safehouse/labs"', result.stdout)
        self.assertIn('safehouse defaults set engagement --path "$HOME/safehouse/engagements"', result.stdout)
        self.assertIn('safehouse new lab "PortSwigger SQLi"', result.stdout)
        self.assertIn('safehouse doctor', result.stdout)
        self.assertNotIn('vault-template', result.stdout)
        self.assertNotIn('category          ', result.stdout)

    def test_doctor_and_resize_help_use_public_operator_wording(self) -> None:
        doctor_help = subprocess.run(
            [sys.executable, str(ROOT / 'safehouse.py'), 'doctor', '--help'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        resize_help = subprocess.run(
            [sys.executable, str(ROOT / 'safehouse.py'), 'resize', '--help'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(doctor_help.returncode, 0, doctor_help.stderr)
        self.assertIn('safehouse doctor --json', doctor_help.stdout)
        self.assertNotIn('smoke-real-veracrypt', doctor_help.stdout)
        self.assertEqual(resize_help.returncode, 0, resize_help.stderr)
        self.assertIn('Safety:', resize_help.stdout)
        self.assertNotIn('Stage 1 safety', resize_help.stdout)

    def test_version_flag_prints_stable_cli_identity_without_config_access(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            env = os.environ.copy()
            env['SAFEHOUSE_HOME'] = str(Path(td) / 'missing-home')

            safehouse_result = subprocess.run(
                [sys.executable, str(ROOT / 'safehouse.py'), '--version'],
                cwd=ROOT,
                env=env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(safehouse_result.returncode, 0, safehouse_result.stderr)
            self.assertRegex(safehouse_result.stdout, r'^safehouse \d+\.\d+\.\d+(?:-[a-z0-9.-]+)?\n$')
            self.assertFalse((Path(td) / 'missing-home').exists())

    def test_about_flag_prints_identity_without_config_access(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing_home = Path(td) / 'missing-home'
            env = os.environ.copy()
            env['SAFEHOUSE_HOME'] = str(missing_home)

            result = subprocess.run(
                [sys.executable, str(ROOT / 'safehouse.py'), '--about'],
                cwd=ROOT,
                env=env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.startswith('Safehouse\n\n'))
            self.assertIn('local-first workspaces for pentest labs and encrypted engagement work', result.stdout)
            self.assertIn('Author: Brian Brandson', result.stdout)
            self.assertIn('License: MIT', result.stdout)
            self.assertFalse(missing_home.exists())


    @unittest.skipUnless(HAS_PRIVATE_RELEASE_TOOLING, 'private release tooling is not part of the public source tree')
    def test_public_candidate_builder_lists_only_public_allowlist(self) -> None:
        result = subprocess.run(
            [str(ROOT / 'scripts' / 'build-public-candidate'), '--list'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        files = result.stdout.splitlines()
        self.assertIn('CONTRIBUTING.md', files)
        self.assertIn('safehouse.py', files)
        self.assertIn('pyproject.toml', files)
        self.assertIn('uv.lock', files)
        self.assertIn('LICENSE', files)
        self.assertIn('README.md', files)
        self.assertIn('docs/manual.md', files)
        self.assertIn('scripts/check', files)
        self.assertNotIn('docs/real-veracrypt-smoke.md', files)
        self.assertNotIn('scripts/build-public-candidate', files)
        self.assertNotIn('docs/council/2026-09-01-stage-1-design-review.md', files)
        self.assertNotIn('docs/plans/2026-09-01-obsidian-profile-scaffolding.md', files)
        self.assertFalse(any(part in path for path in files for part in ('.hermes', 'AGENTS.md', '__pycache__')))

    @unittest.skipUnless(HAS_PRIVATE_RELEASE_TOOLING, 'private release tooling is not part of the public source tree')
    def test_public_candidate_builder_copies_allowlist_without_internal_docs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'public-candidate'
            result = subprocess.run(
                [str(ROOT / 'scripts' / 'build-public-candidate'), '--out', str(out)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((out / 'CONTRIBUTING.md').is_file())
            self.assertTrue((out / 'safehouse.py').is_file())
            self.assertTrue((out / 'pyproject.toml').is_file())
            self.assertTrue((out / 'uv.lock').is_file())
            self.assertTrue((out / 'LICENSE').is_file())
            self.assertTrue((out / 'docs' / 'manual.md').is_file())
            self.assertTrue((out / 'scripts' / 'check').is_file())
            self.assertFalse((out / 'scripts' / 'build-public-candidate').exists())
            self.assertFalse((out / 'docs' / 'council').exists())
            self.assertFalse((out / 'docs' / 'plans').exists())
            self.assertFalse((out / '.hermes').exists())
            self.assertIn('Public candidate written:', result.stdout)

    @unittest.skipUnless(HAS_PRIVATE_RELEASE_TOOLING, 'private release tooling is not part of the public source tree')
    def test_public_candidate_leak_scan_uses_redacted_no_git_scan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            candidate = td_path / 'public-candidate'
            fake_bin = td_path / 'bin'
            fake_bin.mkdir()
            fake_gitleaks = fake_bin / 'gitleaks'
            fake_gitleaks.write_text(
                '#!/usr/bin/env bash\nprintf "%s\\n" "$@" >"$SAFEHOUSE_FAKE_GITLEAKS_ARGS"\n',
                encoding='utf-8',
            )
            fake_gitleaks.chmod(0o700)

            build = subprocess.run(
                [str(ROOT / 'scripts' / 'build-public-candidate'), '--out', str(candidate)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            env = os.environ.copy()
            env['PATH'] = f"{fake_bin}:{env['PATH']}"
            env['SAFEHOUSE_FAKE_GITLEAKS_ARGS'] = str(td_path / 'args.txt')
            scan = subprocess.run(
                [str(ROOT / 'scripts' / 'scan-public-candidate'), str(candidate)],
                cwd=ROOT,
                env=env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(build.returncode, 0, build.stderr)
            self.assertEqual(scan.returncode, 0, scan.stderr)
            args = (td_path / 'args.txt').read_text(encoding='utf-8').splitlines()
            self.assertEqual(args[:2], ['detect', '--source'])
            self.assertEqual(args[2], str(candidate))
            self.assertIn('--no-git', args)
            self.assertIn('--redact', args)
            self.assertIn('--verbose', args)
            self.assertIn('--no-banner', args)
            self.assertIn('Leak scan passed:', scan.stdout)

    @unittest.skipUnless(HAS_PRIVATE_RELEASE_TOOLING, 'private release tooling is not part of the public source tree')
    def test_public_candidate_readiness_requires_license_before_release(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            candidate = Path(td) / 'candidate'
            build = subprocess.run(
                [str(ROOT / 'scripts' / 'build-public-candidate'), '--out', str(candidate)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            (candidate / 'LICENSE').unlink()
            result = subprocess.run(
                [str(ROOT / 'scripts' / 'check-public-candidate'), str(candidate)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(build.returncode, 0, build.stderr)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Missing required public release file: LICENSE', result.stderr)

    @unittest.skipUnless(HAS_PRIVATE_RELEASE_TOOLING, 'private release tooling is not part of the public source tree')
    def test_public_candidate_readiness_checks_required_files_and_runs_leak_scan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            candidate = td_path / 'candidate'
            fake_bin = td_path / 'bin'
            fake_bin.mkdir()
            fake_gitleaks = fake_bin / 'gitleaks'
            fake_gitleaks.write_text(
                '#!/usr/bin/env bash\nprintf "%s\\n" "$@" >"$SAFEHOUSE_FAKE_GITLEAKS_ARGS"\n',
                encoding='utf-8',
            )
            fake_gitleaks.chmod(0o700)
            build = subprocess.run(
                [str(ROOT / 'scripts' / 'build-public-candidate'), '--out', str(candidate)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            env = os.environ.copy()
            env['PATH'] = f"{fake_bin}:{env['PATH']}"
            env['SAFEHOUSE_FAKE_GITLEAKS_ARGS'] = str(td_path / 'args.txt')

            result = subprocess.run(
                [str(ROOT / 'scripts' / 'check-public-candidate'), str(candidate)],
                cwd=ROOT,
                env=env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(build.returncode, 0, build.stderr)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Release readiness passed:', result.stdout)
            args = (td_path / 'args.txt').read_text(encoding='utf-8').splitlines()
            self.assertEqual(args[:2], ['detect', '--source'])
            self.assertEqual(args[2], str(candidate))
            self.assertIn('--redact', args)

    @unittest.skipUnless(HAS_PRIVATE_RELEASE_TOOLING, 'private release tooling is not part of the public source tree')
    def test_public_candidate_leak_scan_refuses_internal_docs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'candidate'
            (source / 'docs' / 'council').mkdir(parents=True)
            (source / 'docs' / 'council' / 'notes.md').write_text('internal\n', encoding='utf-8')

            result = subprocess.run(
                [str(ROOT / 'scripts' / 'scan-public-candidate'), str(source)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Refusing public scan candidate with internal path:', result.stderr)

    def test_new_help_explains_defaults_secrets_and_examples(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / 'safehouse.py'), 'new', '--help'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Create a lab or engagement Safehouse from configured defaults.', result.stdout)
        self.assertIn('lab: plain Safehouse created under lab.path', result.stdout)
        self.assertIn('container file:', result.stdout)
        self.assertIn('mounted Safehouse:', result.stdout)
        self.assertIn('readable Safehouse mounted at engagement.path/SLUG/mount/', result.stdout)
        self.assertIn('PATH', result.stdout)
        self.assertIn('--path', result.stdout)
        self.assertIn('--storage', result.stdout)
        self.assertIn('Prompts for VeraCrypt password; never pass it as an argument.', result.stdout)
        self.assertIn('safehouse defaults show', result.stdout)
        self.assertIn('safehouse new engagement "ACME External"', result.stdout)

    def test_new_engagement_dry_run_accepts_one_time_category_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            override_root = Path(td) / 'override-engagements'

            result = self.run_cli_with_home(
                home,
                'new', '--dry-run',
                '--path', str(override_root),
                'engagement', 'Client Safe',
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, rf'Container path: {override_root}/client-safe/sh-[0-9a-f]{{8}}\.hc')
            self.assertIn(f'Mount path: {override_root}/client-safe/mount', result.stdout)

    def test_new_category_path_storage_size_and_profile_overrides_do_not_mutate_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            root = Path(td) / 'engagements'

            result = self.run_cli_with_home(
                home,
                'new', '--dry-run',
                '--path', str(root),
                '--storage', 'encrypted',
                '--container-size', '2G',
                '--obsidian-profile', 'minimal',
                'lab', 'Client Safe',
            )
            show_result = self.run_cli_with_home(home, 'defaults', 'show')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, rf'Container path: {root}/client-safe/sh-[0-9a-f]{{8}}\.hc')
            self.assertIn(f'Mount path: {root}/client-safe/mount', result.stdout)
            self.assertIn('Storage: encrypted', result.stdout)
            self.assertIn('Size: 2G', result.stdout)
            self.assertIn('Obsidian profile: minimal', result.stdout)
            self.assertEqual(show_result.returncode, 0, show_result.stderr)
            self.assertIn(f'lab.path = {home}/safehouse/labs (built-in)', show_result.stdout)
            self.assertIn('lab.storage = plain (built-in)', show_result.stdout)
            self.assertIn('container-size = 512M (built-in)', show_result.stdout)

    def test_defaults_category_path_and_storage_drive_new_safehouses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_root = Path(td) / 'labs'

            set_result = self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--path', str(lab_root), '--storage', 'plain')
            show_result = self.run_cli_with_home(home, 'defaults', 'show')
            dry_run = self.run_cli_with_home(home, 'new', '--dry-run', 'lab', 'Odyssey')

            self.assertEqual(set_result.returncode, 0, set_result.stderr)
            self.assertIn(f'lab.path = {lab_root}', set_result.stdout)
            self.assertIn('lab.storage = plain', set_result.stdout)
            self.assertEqual(show_result.returncode, 0, show_result.stderr)
            self.assertIn(f'lab.path = {lab_root} (configured)', show_result.stdout)
            self.assertIn('lab.storage = plain (configured)', show_result.stdout)
            self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
            self.assertIn(f'Safehouse path: {lab_root}/odyssey', dry_run.stdout)

    def test_category_filters_and_retired_surface_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Odyssey', slug='odyssey', category='lab', storage='plain',
                container_path='', mount_path=str(Path(td) / 'labs' / 'odyssey'), size='', filesystem='', phase='ready',
            ))
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-22222222', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(Path(td) / 'engagements' / 'client-safe' / 'sh-22222222.hc'), mount_path=str(Path(td) / 'engagements' / 'client-safe' / 'mount'), size='512M', filesystem='ext4', phase='closed',
            ))

            retired_type = self.run_cli_with_home(home, 'type', 'list')
            retired_category = self.run_cli_with_home(home, 'category', 'list')
            retired_template = self.run_cli_with_home(home, 'vault-template', 'list')
            labs = self.run_cli_with_home(home, 'list', '--category', 'lab')
            encrypted = self.run_cli_with_home(home, 'list', '--storage', 'encrypted', '--json')

            self.assertNotEqual(retired_type.returncode, 0)
            self.assertNotEqual(retired_category.returncode, 0)
            self.assertNotEqual(retired_template.returncode, 0)
            self.assertEqual(labs.returncode, 0, labs.stderr)
            self.assertIn('Odyssey', labs.stdout)
            self.assertNotIn('Client Safe', labs.stdout)
            self.assertEqual(encrypted.returncode, 0, encrypted.stderr)
            payload = json.loads(encrypted.stdout)
            self.assertEqual(payload['count'], 1)
            self.assertEqual(payload['safehouses'][0]['category'], 'engagement')
            self.assertNotIn('type', payload['safehouses'][0])


    def test_lifecycle_help_uses_mount_and_unmount_without_legacy_commands(self) -> None:
        mount_help = subprocess.run(
            [sys.executable, str(ROOT / 'safehouse.py'), 'mount', '--help'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        unmount_help = subprocess.run(
            [sys.executable, str(ROOT / 'safehouse.py'), 'unmount', '--help'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        retired_open = subprocess.run([sys.executable, str(ROOT / 'safehouse.py'), 'open'], cwd=ROOT, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        retired_close = subprocess.run([sys.executable, str(ROOT / 'safehouse.py'), 'close'], cwd=ROOT, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        self.assertEqual(mount_help.returncode, 0, mount_help.stderr)
        self.assertEqual(unmount_help.returncode, 0, unmount_help.stderr)
        self.assertIn('Mount a known encrypted Safehouse by id, exact name, or slug.', mount_help.stdout)
        self.assertIn('Refuses plain labs and occupied mount paths.', mount_help.stdout)
        self.assertIn('safehouse status', mount_help.stdout)
        self.assertIn('Unmount a known encrypted Safehouse with normal VeraCrypt unmount.', unmount_help.stdout)
        self.assertIn('No force unmount or auto-unmount in Stage 1.', unmount_help.stdout)
        self.assertIn('safehouse unmount "ACME External"', unmount_help.stdout)
        self.assertNotEqual(retired_open.returncode, 0)
        self.assertNotEqual(retired_close.returncode, 0)
        self.assertIn("invalid choice: 'open'", retired_open.stderr)
        self.assertIn("invalid choice: 'close'", retired_close.stderr)

    def test_legacy_base_and_platform_flags_are_rejected_by_parser(self) -> None:
        parser = safehouse.build_parser()

        with self.assertRaises(SystemExit):
            parser.parse_args(['new', 'lab', 'Existing', '--base', '/tmp/safehouse-test'])
        with self.assertRaises(SystemExit):
            parser.parse_args(['new', 'lab', 'Existing', '--platform', 'Smoke'])

    def test_app_paths_uses_injected_home_not_real_home(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td))

            self.assertEqual(paths.config_dir, Path(td) / '.config' / 'safehouse')
            self.assertEqual(paths.config_file, Path(td) / '.config' / 'safehouse' / 'config.ini')
            self.assertEqual(paths.state_file, Path(td) / '.config' / 'safehouse' / 'state.json')
            self.assertEqual(paths.profile_dir, Path(td) / '.config' / 'safehouse' / 'obsidian-profiles')

    def test_defaults_set_show_and_clear_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = safehouse.ConfigStore(safehouse.AppPaths.from_home(Path(td)))

            store.set_category_default('engagement', 'path', '/tmp/safehouse-engagements')
            store.set_category_default('engagement', 'container-size', '512M')
            store.set_category_default('engagement', 'obsidian-profile', 'minimal')
            store.set_category_default('lab', 'storage', 'plain')
            store.set_category_default('engagement', 'storage', 'encrypted')
            store.set_category_default('lab', 'path', '/tmp/labs')

            self.assertEqual(store.get_category_default('engagement', 'path'), '/tmp/safehouse-engagements')
            self.assertEqual(store.category_defaults('lab'), {'path': '/tmp/labs', 'storage': 'plain'})
            self.assertEqual(store.category_defaults('engagement'), {
                'container-size': '512M',
                'obsidian-profile': 'minimal',
                'path': '/tmp/safehouse-engagements',
                'storage': 'encrypted',
            })

            store.clear_category_default('engagement', 'obsidian-profile')
            self.assertEqual(store.get_category_default('engagement', 'obsidian-profile'), 'minimal')
            self.assertNotIn('obsidian-profile', store.category_defaults('engagement'))

    def test_config_files_use_restrictive_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = safehouse.ConfigStore(safehouse.AppPaths.from_home(Path(td)))

            store.set_category_default('engagement', 'path', '/tmp/safehouse-containers')

            dir_mode = stat.S_IMODE(store.paths.config_dir.stat().st_mode)
            file_mode = stat.S_IMODE(store.paths.config_file.stat().st_mode)
            self.assertEqual(dir_mode, 0o700)
            self.assertEqual(file_mode, 0o600)

    def test_defaults_reject_unknown_keys_and_invalid_sizes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = safehouse.ConfigStore(safehouse.AppPaths.from_home(Path(td)))

            with self.assertRaises(ValueError):
                store.set_category_default('lab', 'base', '/tmp/legacy')
            with self.assertRaises(ValueError):
                store.set_category_default('lab', 'container-size', 'five gigs')
            with self.assertRaises(ValueError):
                store.set_category_default('lab', 'storage', 'encrypted-ish')

    def test_config_store_refuses_symlinked_config_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td))
            paths.config_dir.mkdir(parents=True)
            paths.config_file.symlink_to(Path(td) / 'elsewhere.ini')
            store = safehouse.ConfigStore(paths)

            with self.assertRaises(RuntimeError):
                store.set_category_default('engagement', 'path', '/tmp/safehouse-containers')

    def test_defaults_cli_flags_show_and_clear_uses_safehouse_home(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)

            set_result = self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--container-size', '2G')
            show_result = self.run_cli_with_home(home, 'defaults', 'show', 'lab')
            clear_result = self.run_cli_with_home(home, 'defaults', 'clear', 'lab', '--container-size')
            final_show_result = self.run_cli_with_home(home, 'defaults', 'show', 'lab')

            self.assertEqual(set_result.returncode, 0, set_result.stderr)
            self.assertIn('lab.container-size = 2G', set_result.stdout)
            self.assertEqual(show_result.returncode, 0, show_result.stderr)
            self.assertIn('lab.container-size = 2G (configured)', show_result.stdout)
            self.assertEqual(clear_result.returncode, 0, clear_result.stderr)
            self.assertIn('lab.container-size reverted to built-in default', clear_result.stdout)
            self.assertEqual(final_show_result.returncode, 0, final_show_result.stderr)
            self.assertIn('lab.container-size = 512M (built-in)', final_show_result.stdout)

    def test_builtin_defaults_allow_lab_dry_run_without_setup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'

            result = self.run_cli_with_home(home, 'new', '--dry-run', 'lab', 'Fresh Lab')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f'Safehouse path: {home}/safehouse/labs/fresh-lab', result.stdout)
            self.assertIn('Would prompt for VeraCrypt password: no', result.stdout)

    def test_builtin_defaults_allow_engagement_dry_run_without_setup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'

            result = self.run_cli_with_home(home, 'new', '--dry-run', 'engagement', 'Fresh Client')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, rf'Container path: {home}/safehouse/engagements/fresh-client/sh-[0-9a-f]{{8}}\.hc')
            self.assertIn(f'Mount path: {home}/safehouse/engagements/fresh-client/mount', result.stdout)
            self.assertIn('Size: 512M', result.stdout)
            self.assertIn('Obsidian profile: minimal', result.stdout)

    def test_defaults_clear_requires_setting_or_all_flag(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'

            set_result = self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--container-size', '2G')
            clear_result = self.run_cli_with_home(home, 'defaults', 'clear')
            all_result = self.run_cli_with_home(home, 'defaults', 'clear', '--all')
            show_result = self.run_cli_with_home(home, 'defaults', 'show')

            self.assertEqual(set_result.returncode, 0, set_result.stderr)
            self.assertNotEqual(clear_result.returncode, 0)
            self.assertIn('clear requires CATEGORY plus field flags, or --all', clear_result.stderr)
            self.assertEqual(all_result.returncode, 0, all_result.stderr)
            self.assertIn('all configured defaults reverted to built-in defaults', all_result.stdout)
            self.assertEqual(show_result.returncode, 0, show_result.stderr)
            self.assertIn(f'lab.container-size = 512M (built-in)', show_result.stdout)
            self.assertIn(f'lab.path = {home}/safehouse/labs (built-in)', show_result.stdout)

    def test_defaults_cli_accepts_flags_for_all_default_settings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_dir = Path(td) / 'labs'
            container_dir = Path(td) / 'containers'

            lab_result = self.run_cli_with_home(
                home,
                'defaults',
                'set',
                'lab',
                '--path', str(lab_dir),
                '--storage', 'encrypted',
                '--container-size', '2G',
                '--obsidian-profile', 'minimal',
            )
            engagement_result = self.run_cli_with_home(
                home,
                'defaults',
                'set',
                'engagement',
                '--path', str(container_dir),
                '--storage', 'plain',
                '--container-size', '3G',
                '--obsidian-profile', 'minimal',
            )
            show_result = self.run_cli_with_home(home, 'defaults', 'show')

            self.assertEqual(lab_result.returncode, 0, lab_result.stderr)
            self.assertIn('lab.container-size = 2G', lab_result.stdout)
            self.assertIn('lab.obsidian-profile = minimal', lab_result.stdout)
            self.assertEqual(engagement_result.returncode, 0, engagement_result.stderr)
            self.assertEqual(show_result.returncode, 0, show_result.stderr)
            self.assertIn(f'lab.path = {lab_dir} (configured)', show_result.stdout)
            self.assertIn(f'engagement.path = {container_dir} (configured)', show_result.stdout)
            self.assertIn('lab.container-size = 2G (configured)', show_result.stdout)
            self.assertIn('engagement.container-size = 3G (configured)', show_result.stdout)
            self.assertIn('lab.obsidian-profile = minimal (configured)', show_result.stdout)
            self.assertIn('engagement.obsidian-profile = minimal (configured)', show_result.stdout)
            self.assertIn('lab.storage = encrypted (configured)', show_result.stdout)
            self.assertIn('engagement.storage = plain (configured)', show_result.stdout)

    def test_defaults_set_uses_positional_category_for_builtin_categories_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_result = self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--path', str(Path(td) / 'labs'))
            ctf_result = self.run_cli_with_home(home, 'defaults', 'set', 'ctf', '--path', str(Path(td) / 'ctf'))
            removed_global_result = self.run_cli_with_home(home, 'defaults', 'set', '--container-size', '2G', '--obsidian-profile', 'minimal')
            show_all = self.run_cli_with_home(home, 'defaults', 'show')

            self.assertEqual(lab_result.returncode, 0, lab_result.stderr)
            self.assertNotEqual(ctf_result.returncode, 0)
            self.assertNotEqual(removed_global_result.returncode, 0)
            self.assertIn('the following arguments are required: CATEGORY', removed_global_result.stderr)
            self.assertIn('lab.path = ', show_all.stdout)
            self.assertNotIn('ctf.path', show_all.stdout)

    def test_defaults_rejects_removed_category_flag(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            root = Path(td) / 'ctf'

            set_result = self.run_cli_with_home(home, 'defaults', 'set', '--category', 'ctf', '--path', str(root))
            show_result = self.run_cli_with_home(home, 'defaults', 'show', '--category', 'ctf')
            clear_result = self.run_cli_with_home(home, 'defaults', 'clear', '--category', 'ctf', '--path')

            self.assertNotEqual(set_result.returncode, 0)
            self.assertNotEqual(show_result.returncode, 0)
            self.assertNotEqual(clear_result.returncode, 0)
            self.assertIn("invalid choice: 'ctf'", set_result.stderr)
            self.assertIn("invalid choice: 'ctf'", show_result.stderr)
            self.assertIn("invalid choice: 'ctf'", clear_result.stderr)

    def test_defaults_retires_category_subcommands_and_legacy_default_flags(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'

            lab_subcommand = self.run_cli_with_home(home, 'defaults', 'lab', '--path', str(Path(td) / 'labs'))
            old_flag = self.run_cli_with_home(home, 'defaults', '--lab-dir', str(Path(td) / 'labs'))

            self.assertNotEqual(lab_subcommand.returncode, 0)
            self.assertIn("invalid choice: 'lab'", lab_subcommand.stderr)
            self.assertNotEqual(old_flag.returncode, 0)
            self.assertIn("invalid choice", old_flag.stderr)


    def test_defaults_cli_rejects_legacy_key_value_set_and_base_key(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = self.run_cli_with_home(Path(td), 'defaults', 'set', 'base', '/tmp/legacy')

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid choice: 'base'", result.stderr)

    def test_defaults_help_explains_flags_storage_modes_and_clear_all(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / 'safehouse.py'), 'defaults', 'set', '--help'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('usage: safehouse defaults', result.stdout)
        self.assertIn('Available settings:', result.stdout)
        self.assertIn('safehouse defaults set lab --path', result.stdout)
        self.assertIn('CATEGORY --path PATH', result.stdout)
        self.assertIn('CATEGORY --storage MODE', result.stdout)
        self.assertIn('CATEGORY --container-size SIZE', result.stdout)
        self.assertIn('CATEGORY --obsidian-profile NAME', result.stdout)
        self.assertIn('safehouse defaults clear lab --obsidian-profile', result.stdout)
        self.assertIn('--obsidian-profile PROFILE', result.stdout)
        self.assertNotIn('--category', result.stdout)
        self.assertNotIn('KEY         default to set', result.stdout)
        self.assertNotIn('Common defaults:', result.stdout)

    def test_obsidian_profile_import_refuses_existing_profile(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault'
            obsidian = source / '.obsidian'
            obsidian.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{"accentColor":"blue"}\n', encoding='utf-8')

            first = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))
            second = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn('imported obsidian profile work', first.stdout)
            self.assertNotEqual(second.returncode, 0)
            self.assertIn('obsidian profile already exists: work', second.stderr)



    def test_obsidian_profile_import_excludes_workspace_cache_and_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault'
            obsidian = source / '.obsidian'
            snippets = obsidian / 'snippets'
            plugins = obsidian / 'plugins' / 'calendar'
            cache = obsidian / 'cache'
            logs = obsidian / 'logs'
            snippets.mkdir(parents=True)
            plugins.mkdir(parents=True)
            cache.mkdir(parents=True)
            logs.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{"accentColor":"blue"}\n', encoding='utf-8')
            (obsidian / 'workspace.json').write_text('{"private":"layout state"}\n', encoding='utf-8')
            (obsidian / 'workspace-mobile.json').write_text('{"private":"mobile state"}\n', encoding='utf-8')
            (snippets / 'safehouse.css').write_text('body { color: red; }\n', encoding='utf-8')
            (plugins / 'main.js').write_text('/* plugin code */\n', encoding='utf-8')
            (plugins / 'data.json').write_text('{"setting":true}\n', encoding='utf-8')
            (cache / 'secret-cache.json').write_text('{"client":"nope"}\n', encoding='utf-8')
            (logs / 'obsidian.log').write_text('local window title\n', encoding='utf-8')

            result = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))

            profile = safehouse.AppPaths.from_home(home).profile_dir / 'work'
            manifest = safehouse.AppPaths.from_home(home).profile_dir / 'work.import-manifest.json'
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((profile / 'app.json').is_file())
            self.assertTrue((profile / 'snippets' / 'safehouse.css').is_file())
            self.assertTrue((profile / 'plugins' / 'calendar' / 'main.js').is_file())
            self.assertTrue((profile / 'plugins' / 'calendar' / 'data.json').is_file())
            self.assertFalse((profile / 'workspace.json').exists())
            self.assertFalse((profile / 'workspace-mobile.json').exists())
            self.assertFalse((profile / 'cache').exists())
            self.assertFalse((profile / 'logs').exists())
            manifest_text = manifest.read_text(encoding='utf-8')
            self.assertIn('app.json', manifest_text)
            self.assertIn('plugins/calendar/main.js', manifest_text)
            self.assertIn('plugins/calendar/data.json', manifest_text)
            self.assertIn('excluded', manifest_text)
            self.assertIn('community plugin code is user-supplied executable code', result.stdout)

    def test_obsidian_profile_import_rejects_symlinks_inside_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault'
            obsidian = source / '.obsidian'
            obsidian.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{}\n', encoding='utf-8')
            (obsidian / 'linked.json').symlink_to(obsidian / 'app.json')

            result = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('refusing symlink in obsidian profile source', result.stderr)
            self.assertFalse((safehouse.AppPaths.from_home(home).profile_dir / 'work').exists())

    def test_obsidian_profile_import_rejects_symlinked_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            real_source = Path(td) / 'real-vault'
            obsidian = real_source / '.obsidian'
            obsidian.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{}\n', encoding='utf-8')
            linked_source = Path(td) / 'linked-vault'
            linked_source.symlink_to(real_source)

            result = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(linked_source))

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('refusing symlinked obsidian profile source directory', result.stderr)
            self.assertFalse((safehouse.AppPaths.from_home(home).profile_dir / 'work').exists())

    def test_obsidian_profile_list_verbose_reports_safe_status_without_config_contents(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault'
            obsidian = source / '.obsidian'
            obsidian.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{"accentColor":"secret-blue"}\n', encoding='utf-8')
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))

            result = self.run_cli_with_home(home, 'obsidian-profile', 'list', '--verbose')

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('NAME', result.stdout)
            self.assertIn('minimal', result.stdout)
            self.assertIn('built-in', result.stdout)
            self.assertIn('work', result.stdout)
            self.assertIn('imported', result.stdout)
            self.assertNotIn('secret-blue', result.stdout)

    def test_obsidian_profile_list_includes_builtin_minimal_without_imports(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = self.run_cli_with_home(Path(td) / 'home', 'obsidian-profile', 'list')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Built-in Obsidian profiles:', result.stdout)
            self.assertIn('  minimal', result.stdout)
            self.assertIn('Imported Obsidian profiles:', result.stdout)
            self.assertIn('  none', result.stdout)
            self.assertNotIn('No Obsidian profiles imported', result.stdout)

    def test_obsidian_profile_list_verbose_reports_manifest_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            profile = paths.profile_dir / 'work'
            profile.mkdir(parents=True)
            (profile / 'app.json').write_text('{"accentColor":"secret-blue"}\n', encoding='utf-8')

            result = self.run_cli_with_home(home, 'obsidian-profile', 'list', '--verbose')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('work', result.stdout)
            self.assertIn('manifest-missing', result.stdout)
            self.assertNotIn('secret-blue', result.stdout)

    def test_obsidian_profile_help_explains_import_apply_and_verify_roles(self) -> None:
        top = subprocess.run(
            [sys.executable, str(ROOT / 'safehouse.py'), 'obsidian-profile', '--help'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        imported = subprocess.run(
            [sys.executable, str(ROOT / 'safehouse.py'), 'obsidian-profile', 'import', '--help'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        verify = subprocess.run(
            [sys.executable, str(ROOT / 'safehouse.py'), 'obsidian-profile', 'verify', '--help'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(top.returncode, 0, top.stderr)
        self.assertIn('import stores a reusable copy; apply writes it to a Safehouse', top.stdout)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertIn('Copy only reusable .obsidian config into the Safehouse profile store.', imported.stdout)
        self.assertIn('Does not apply the profile to any existing Safehouse.', imported.stdout)
        self.assertIn('Then set it as a default or apply it explicitly.', imported.stdout)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertIn('Check a stored imported profile against its import manifest.', verify.stdout)
        self.assertIn('Use this before trusting or applying a copied profile', verify.stdout)
        self.assertIn('apply runs this check automatically', verify.stdout)

    def test_obsidian_profile_show_summarizes_manifest_without_dumping_config(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault'
            obsidian = source / '.obsidian'
            plugin = obsidian / 'plugins' / 'calendar'
            cache = obsidian / 'cache'
            plugin.mkdir(parents=True)
            cache.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{"accentColor":"secret-blue"}\n', encoding='utf-8')
            (obsidian / 'community-plugins.json').write_text('["calendar"]\n', encoding='utf-8')
            (plugin / 'main.js').write_text('/* plugin */\n', encoding='utf-8')
            (plugin / 'data.json').write_text('{"apiKey":"do-not-print"}\n', encoding='utf-8')
            (cache / 'state.json').write_text('{"client":"do-not-copy"}\n', encoding='utf-8')
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))

            result = self.run_cli_with_home(home, 'obsidian-profile', 'show', 'work')

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Profile: work', result.stdout)
            self.assertIn('Source: imported', result.stdout)
            self.assertIn(str(obsidian.resolve()), result.stdout)
            self.assertIn('Imported files: 4', result.stdout)
            self.assertIn('Excluded paths: 2', result.stdout)
            self.assertIn('Community plugins: calendar', result.stdout)
            self.assertIn('Manifest:', result.stdout)
            self.assertIn('community plugin code is user-supplied executable code', result.stdout)
            self.assertNotIn('secret-blue', result.stdout)
            self.assertNotIn('do-not-print', result.stdout)

    def test_obsidian_profile_show_summarizes_builtin_minimal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = self.run_cli_with_home(Path(td) / 'home', 'obsidian-profile', 'show', 'minimal')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Profile: minimal', result.stdout)
            self.assertIn('Source: built-in', result.stdout)
            self.assertIn('Imported files: 6', result.stdout)
            self.assertIn('Community plugins: none', result.stdout)
            self.assertNotIn('{"alwaysUpdateLinks"', result.stdout)

    def test_obsidian_profile_verify_accepts_untouched_import(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault'
            obsidian = source / '.obsidian'
            plugin = obsidian / 'plugins' / 'calendar'
            plugin.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{"accentColor":"secret-blue"}\n', encoding='utf-8')
            (obsidian / 'community-plugins.json').write_text('["calendar"]\n', encoding='utf-8')
            (plugin / 'main.js').write_text('/* plugin */\n', encoding='utf-8')
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))

            result = self.run_cli_with_home(home, 'obsidian-profile', 'verify', 'work')

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Profile: work', result.stdout)
            self.assertIn('OK imported files verified: 3', result.stdout)
            self.assertIn('Manifest:', result.stdout)
            self.assertNotIn('secret-blue', result.stdout)

    def test_obsidian_profile_verify_reports_manifest_drift_without_dumping_config(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault'
            obsidian = source / '.obsidian'
            plugin = obsidian / 'plugins' / 'calendar'
            plugin.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{"accentColor":"secret-blue"}\n', encoding='utf-8')
            (obsidian / 'community-plugins.json').write_text('["calendar"]\n', encoding='utf-8')
            (plugin / 'main.js').write_text('/* plugin */\n', encoding='utf-8')
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))
            profile = safehouse.AppPaths.from_home(home).profile_dir / 'work'
            (profile / 'app.json').write_text('{"accentColor":"changed-secret"}\n', encoding='utf-8')
            (profile / 'community-plugins.json').unlink()

            result = self.run_cli_with_home(home, 'obsidian-profile', 'verify', 'work')

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(result.returncode, 1)
            self.assertIn('Profile: work', result.stdout)
            self.assertIn('FAIL hash mismatch: app.json', result.stdout)
            self.assertIn('FAIL missing file: community-plugins.json', result.stdout)
            self.assertIn('NEXT re-import with `safehouse obsidian-profile replace work --from SOURCE`', result.stdout)
            self.assertNotIn('changed-secret', result.stdout)

    def test_obsidian_profile_verify_accepts_builtin_minimal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = self.run_cli_with_home(Path(td) / 'home', 'obsidian-profile', 'verify', 'minimal')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Profile: minimal', result.stdout)
            self.assertIn('OK built-in profile available', result.stdout)

    def test_obsidian_profile_verify_all_reports_all_profiles_and_nonzero_on_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault'
            obsidian = source / '.obsidian'
            obsidian.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{"accentColor":"secret-blue"}\n', encoding='utf-8')
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))
            profile = safehouse.AppPaths.from_home(home).profile_dir / 'work'
            (profile / 'app.json').write_text('{"accentColor":"changed-secret"}\n', encoding='utf-8')

            result = self.run_cli_with_home(home, 'obsidian-profile', 'verify', '--all')

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(result.returncode, 1)
            self.assertIn('Profile: minimal', result.stdout)
            self.assertIn('OK built-in profile available', result.stdout)
            self.assertIn('Profile: work', result.stdout)
            self.assertIn('FAIL hash mismatch: app.json', result.stdout)
            self.assertNotIn('changed-secret', result.stdout)

    def test_obsidian_profile_verify_all_succeeds_when_all_profiles_verify(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault'
            obsidian = source / '.obsidian'
            obsidian.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{"accentColor":"secret-blue"}\n', encoding='utf-8')
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))

            result = self.run_cli_with_home(home, 'obsidian-profile', 'verify', '--all')

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Profile: minimal', result.stdout)
            self.assertIn('Profile: work', result.stdout)
            self.assertIn('OK imported files verified: 1', result.stdout)
            self.assertNotIn('secret-blue', result.stdout)

    def test_obsidian_profile_apply_dry_run_reports_create_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            safehouse_root = Path(td) / 'safehouse-root'
            safehouse_root.mkdir()

            result = self.run_cli_with_home(home, 'obsidian-profile', 'apply', '--dry-run', 'minimal', '--to', str(safehouse_root))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('DRY-RUN would apply obsidian profile minimal', result.stdout)
            self.assertIn(str(safehouse_root / '.obsidian'), result.stdout)
            self.assertFalse((safehouse_root / '.obsidian').exists())

    def test_obsidian_profile_apply_refuses_unregistered_target_before_replacing_profile(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            target = Path(td) / 'unregistered-vault'
            existing = target / '.obsidian'
            existing.mkdir(parents=True)
            (existing / 'app.json').write_text('{"accentColor":"keep-me"}\n', encoding='utf-8')

            result = self.run_cli_with_home(home, 'obsidian-profile', 'apply', 'minimal', '--to', str(target))

            self.assertEqual(result.returncode, 2)
            self.assertIn('registered Safehouse root', result.stderr)
            self.assertEqual((existing / 'app.json').read_text(encoding='utf-8'), '{"accentColor":"keep-me"}\n')

    def test_obsidian_profile_apply_requires_to_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            safehouse_root = Path(td) / 'safehouse-root'
            safehouse_root.mkdir()

            result = self.run_cli_with_home(home, 'obsidian-profile', 'apply', '--dry-run', 'minimal', str(safehouse_root))

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('the following arguments are required: --to', result.stderr)
            self.assertFalse((safehouse_root / '.obsidian').exists())

    def test_obsidian_profile_apply_dry_run_reports_replace_without_touching_contents(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            safehouse_root = Path(td) / 'safehouse-root'
            obsidian = safehouse_root / '.obsidian'
            obsidian.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{"accentColor":"secret-blue"}\n', encoding='utf-8')
            safehouse.StateStore(safehouse.AppPaths.from_home(home)).upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Safehouse Root', slug='safehouse-root', category='lab', storage='plain', container_path='', mount_path=str(safehouse_root), size='', filesystem='', phase='ready',
            ))

            result = self.run_cli_with_home(home, 'obsidian-profile', 'apply', '--dry-run', 'minimal', '--to', str(safehouse_root))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('DRY-RUN would replace existing .obsidian directory with obsidian profile minimal', result.stdout)
            self.assertIn(str(obsidian), result.stdout)
            self.assertEqual((obsidian / 'app.json').read_text(encoding='utf-8'), '{"accentColor":"secret-blue"}\n')
            self.assertNotIn('secret-blue', result.stdout)

    def test_obsidian_profile_apply_replaces_existing_profile_directory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault' / '.obsidian'
            safehouse_root = Path(td) / 'safehouse-root'
            existing = safehouse_root / '.obsidian'
            source.mkdir(parents=True)
            safehouse_root.mkdir()
            existing.mkdir()
            (source / 'app.json').write_text('{"theme":"safe"}\n', encoding='utf-8')
            (existing / 'app.json').write_text('{"accentColor":"secret-blue"}\n', encoding='utf-8')
            safehouse.StateStore(safehouse.AppPaths.from_home(home)).upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Safehouse Root', slug='safehouse-root', category='lab', storage='plain', container_path='', mount_path=str(safehouse_root), size='', filesystem='', phase='ready',
            ))
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source.parent))

            dry_run = self.run_cli_with_home(home, 'obsidian-profile', 'apply', '--dry-run', 'work', '--to', str(safehouse_root))
            refused = self.run_cli_with_home(home, 'obsidian-profile', 'apply', 'work', '--to', str(safehouse_root))

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
            self.assertIn('DRY-RUN would replace existing .obsidian directory', dry_run.stdout)
            self.assertEqual(refused.returncode, 2)
            self.assertIn('--yes-replace', refused.stderr)
            self.assertEqual((existing / 'app.json').read_text(encoding='utf-8'), '{"accentColor":"secret-blue"}\n')

            applied = self.run_cli_with_home(home, 'obsidian-profile', 'apply', 'work', '--yes-replace', '--to', str(safehouse_root))
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertIn('applied obsidian profile work', applied.stdout)
            self.assertEqual((existing / 'app.json').read_text(encoding='utf-8'), '{"theme":"safe"}\n')
            self.assertNotIn('secret-blue', dry_run.stdout)
            self.assertNotIn('secret-blue', applied.stdout)

    def test_builtin_minimal_profile_configures_templates_and_snippet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            safehouse_root = Path(td) / 'safehouse-root'
            safehouse_root.mkdir()

            applied = safehouse.apply_obsidian_profile(safehouse.AppPaths.from_home(Path(td) / 'home'), 'minimal', str(safehouse_root))

            self.assertEqual(applied, safehouse_root / '.obsidian')
            self.assertTrue((applied / 'templates.json').is_file())
            self.assertTrue((applied / 'snippets' / 'safehouse.css').is_file())
            templates_config = json.loads((applied / 'templates.json').read_text(encoding='utf-8'))
            self.assertEqual(templates_config['folder'], '_safehouse/templates')

    def test_obsidian_profile_apply_refuses_drifted_import_before_copying(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault' / '.obsidian'
            safehouse_root = Path(td) / 'safehouse-root'
            source.mkdir(parents=True)
            safehouse_root.mkdir()
            (source / 'app.json').write_text('{"theme":"safe"}\n', encoding='utf-8')
            safehouse.StateStore(safehouse.AppPaths.from_home(home)).upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Safehouse Root', slug='safehouse-root', category='lab', storage='plain', container_path='', mount_path=str(safehouse_root), size='', filesystem='', phase='ready',
            ))
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source.parent))
            profile = safehouse.AppPaths.from_home(home).profile_dir / 'work'
            (profile / 'app.json').write_text('{"theme":"changed"}\n', encoding='utf-8')

            result = self.run_cli_with_home(home, 'obsidian-profile', 'apply', 'work', '--to', str(safehouse_root))

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('obsidian profile failed verification before apply', result.stderr)
            self.assertFalse((safehouse_root / '.obsidian').exists())

    def test_obsidian_profile_apply_refuses_stored_symlinks_before_copying(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            source = Path(td) / 'vault' / '.obsidian'
            safehouse_root = Path(td) / 'safehouse-root'
            source.mkdir(parents=True)
            safehouse_root.mkdir()
            (source / 'app.json').write_text('{"theme":"safe"}\n', encoding='utf-8')
            safehouse.StateStore(safehouse.AppPaths.from_home(home)).upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Safehouse Root', slug='safehouse-root', category='lab', storage='plain', container_path='', mount_path=str(safehouse_root), size='', filesystem='', phase='ready',
            ))
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source.parent))
            profile = safehouse.AppPaths.from_home(home).profile_dir / 'work'
            (profile / 'linked.json').symlink_to(profile / 'app.json')

            result = self.run_cli_with_home(home, 'obsidian-profile', 'apply', 'work', '--to', str(safehouse_root))

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('refusing symlink in stored obsidian profile', result.stderr)
            self.assertFalse((safehouse_root / '.obsidian').exists())

    def test_obsidian_profile_replace_is_explicit_and_replaces_existing_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            first_source = Path(td) / 'first-vault' / '.obsidian'
            second_source = Path(td) / 'second-vault' / '.obsidian'
            first_source.mkdir(parents=True)
            second_source.mkdir(parents=True)
            (first_source / 'app.json').write_text('{"theme":"old"}\n', encoding='utf-8')
            (first_source / 'old-only.json').write_text('{}\n', encoding='utf-8')
            (second_source / 'app.json').write_text('{"theme":"new"}\n', encoding='utf-8')
            plugins = second_source / 'plugins' / 'calendar'
            plugins.mkdir(parents=True)
            (plugins / 'main.js').write_text('/* plugin code */\n', encoding='utf-8')

            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(first_source.parent))
            replaced = self.run_cli_with_home(home, 'obsidian-profile', 'replace', 'work', '--from', str(second_source.parent))

            profile = safehouse.AppPaths.from_home(home).profile_dir / 'work'
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(replaced.returncode, 0, replaced.stderr)
            self.assertIn('replaced obsidian profile work', replaced.stdout)
            self.assertEqual((profile / 'app.json').read_text(encoding='utf-8'), '{"theme":"new"}\n')
            self.assertTrue((profile / 'plugins' / 'calendar' / 'main.js').is_file())
            self.assertFalse((profile / 'old-only.json').exists())

    def test_obsidian_profile_replace_requires_existing_profile_and_valid_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            missing = self.run_cli_with_home(home, 'obsidian-profile', 'replace', 'work', '--from', str(Path(td) / 'missing'))

            self.assertNotEqual(missing.returncode, 0)
            self.assertIn('obsidian profile does not exist: work', missing.stderr)

    def test_new_lab_cli_uses_lab_dir_default_without_base_or_veracrypt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_dir = Path(td) / '40_Labs_&_Engagements'
            set_result = self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--path', str(lab_dir))
            result = self.run_cli_with_home(home, 'new', 'lab', 'Odyssey')

            self.assertEqual(set_result.returncode, 0, set_result.stderr)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(str(lab_dir / 'odyssey'), result.stdout)
            self.assertTrue((lab_dir / 'odyssey' / '00_run.md').is_file())
            records = safehouse.StateStore(safehouse.AppPaths.from_home(home)).records()
            self.assertEqual(records[0].storage, 'plain')
            self.assertEqual(records[0].phase, 'ready')

    def test_new_lab_applies_builtin_minimal_obsidian_profile(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_dir = Path(td) / 'labs'
            self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--path', str(lab_dir))

            result = self.run_cli_with_home(home, 'new', 'lab', 'Odyssey')

            self.assertEqual(result.returncode, 0, result.stderr)
            safehouse_root = lab_dir / 'odyssey'
            self.assertTrue((safehouse_root / '.obsidian' / 'app.json').is_file())
            self.assertTrue((safehouse_root / '.obsidian' / 'appearance.json').is_file())
            records = safehouse.StateStore(safehouse.AppPaths.from_home(home)).records()
            self.assertEqual(records[0].phase, 'ready')

    def test_new_lab_applies_configured_custom_obsidian_profile(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_dir = Path(td) / 'labs'
            source = Path(td) / 'source-vault' / '.obsidian'
            source.mkdir(parents=True)
            (source / 'app.json').write_text('{"theme":"obsidian"}\n', encoding='utf-8')
            plugin = source / 'plugins' / 'calendar'
            plugin.mkdir(parents=True)
            (plugin / 'main.js').write_text('/* plugin */\n', encoding='utf-8')
            self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--path', str(lab_dir))
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source.parent))
            defaulted = self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--obsidian-profile', 'work')

            result = self.run_cli_with_home(home, 'new', 'lab', 'Odyssey')

            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(defaulted.returncode, 0, defaulted.stderr)
            self.assertEqual(result.returncode, 0, result.stderr)
            safehouse_root = lab_dir / 'odyssey'
            self.assertEqual((safehouse_root / '.obsidian' / 'app.json').read_text(encoding='utf-8'), '{"theme":"obsidian"}\n')
            self.assertTrue((safehouse_root / '.obsidian' / 'plugins' / 'calendar' / 'main.js').is_file())

    def test_new_lab_fails_clearly_when_configured_obsidian_profile_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_dir = Path(td) / 'labs'
            self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--path', str(lab_dir))
            self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--obsidian-profile', 'ghost')

            result = self.run_cli_with_home(home, 'new', 'lab', 'Odyssey')

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('obsidian profile does not exist: ghost', result.stderr)
            self.assertFalse((lab_dir / 'odyssey' / '.obsidian').exists())

    def test_new_lab_cli_uses_builtin_lab_dir_without_setup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'

            result = self.run_cli_with_home(home, 'new', 'lab', 'Odyssey')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((home / 'safehouse' / 'labs' / 'odyssey' / '00_run.md').is_file())

    def test_new_lab_dry_run_previews_without_creating_safehouse_or_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_dir = Path(td) / 'labs'
            self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--path', str(lab_dir))

            result = self.run_cli_with_home(home, 'new', '--dry-run', 'lab', 'Odyssey')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('DRY-RUN safehouse new lab Odyssey', result.stdout)
            self.assertRegex(result.stdout, r'ID: sh-[0-9a-f]{8}')
            self.assertIn('Storage: plain', result.stdout)
            self.assertIn(f'Safehouse path: {lab_dir / "odyssey"}', result.stdout)
            self.assertIn('Obsidian profile: minimal', result.stdout)
            self.assertIn('Would write state phase: ready', result.stdout)
            self.assertFalse((lab_dir / 'odyssey').exists())
            self.assertEqual(safehouse.StateStore(safehouse.AppPaths.from_home(home)).records(), [])

    def test_new_lab_dry_run_json_reports_scriptable_plan_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_dir = Path(td) / 'labs'
            self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--path', str(lab_dir))

            result = self.run_cli_with_home(home, 'new', '--dry-run', '--json', 'lab', 'Odyssey')

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload['exit_code'], 0)
            self.assertEqual(payload['display_name'], 'Odyssey')
            self.assertRegex(payload['safehouse_id'], r'^sh-[0-9a-f]{8}$')
            self.assertEqual(payload['category'], 'lab')
            self.assertNotIn('type', payload)
            self.assertEqual(payload['storage'], 'plain')
            self.assertNotIn('template', payload)
            self.assertEqual(payload['safehouse_path'], str(lab_dir / 'odyssey'))
            self.assertNotIn('workspace_path', payload)
            self.assertEqual(payload['container_path'], '')
            self.assertEqual(payload['mount_path'], str(lab_dir / 'odyssey'))
            self.assertEqual(payload['obsidian_profile'], 'minimal')
            self.assertFalse(payload['will_prompt'])
            self.assertFalse(payload['will_write'])
            self.assertIn('create scaffold', payload['steps'])
            self.assertEqual(payload['warning'], '')
            self.assertEqual(payload['next'], '')
            self.assertFalse((lab_dir / 'odyssey').exists())
            self.assertEqual(safehouse.StateStore(safehouse.AppPaths.from_home(home)).records(), [])
            self.assertNotIn('password', result.stdout.lower())
            self.assertNotIn('secret', result.stdout.lower())

    def test_new_json_without_dry_run_is_rejected_before_writes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_dir = Path(td) / 'labs'
            self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--path', str(lab_dir))

            result = self.run_cli_with_home(home, 'new', '--json', 'lab', 'Odyssey')

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('--json only works with --dry-run', result.stderr)
            self.assertFalse((lab_dir / 'odyssey').exists())
            self.assertEqual(safehouse.StateStore(safehouse.AppPaths.from_home(home)).records(), [])

    def test_new_lab_dry_run_reports_existing_safehouse_without_touching_contents(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_dir = Path(td) / 'labs'
            safehouse_root = lab_dir / 'odyssey'
            safehouse_root.mkdir(parents=True)
            (safehouse_root / 'notes.md').write_text('keep-me\n', encoding='utf-8')
            self.run_cli_with_home(home, 'defaults', 'set', 'lab', '--path', str(lab_dir))

            result = self.run_cli_with_home(home, 'new', '--dry-run', 'lab', 'Odyssey')

            self.assertEqual(result.returncode, 1)
            self.assertIn(f'DRY-RUN refusing non-empty Safehouse path: {safehouse_root}', result.stdout)
            self.assertIn('NEXT inspect or move the existing path manually before running without --dry-run', result.stdout)
            self.assertEqual((safehouse_root / 'notes.md').read_text(encoding='utf-8'), 'keep-me\n')
            self.assertEqual(safehouse.StateStore(safehouse.AppPaths.from_home(home)).records(), [])

    def test_retired_commands_are_not_available(self) -> None:
        for command in ('adopt', 'layout-migrate', 'status-prefix', 'completion', 'migrate'):
            result = subprocess.run(
                [sys.executable, str(ROOT / 'safehouse.py'), command],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"invalid choice: '{command}'", result.stderr)

    def test_new_engagement_dry_run_reports_blocked_mount_without_backend_or_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            config = safehouse.ConfigStore(paths)
            container_dir = Path(td) / 'containers'
            config.set_category_default('engagement', 'path', str(container_dir))
            blocked_mount = container_dir / 'client-safe' / 'mount'
            blocked_mount.mkdir(parents=True)
            (blocked_mount / 'foreign.txt').write_text('keep-me\n', encoding='utf-8')

            exit_code, lines = safehouse.dry_run_new_safehouse(
                'engagement',
                'Client Safe',
                config,
                paths,
                id_rng=lambda n: b'\x7f:\x9c!',
            )

            output = '\n'.join(lines)
            self.assertEqual(exit_code, 1)
            self.assertIn(f'DRY-RUN refusing unavailable mount path: {blocked_mount}', output)
            self.assertIn('NEXT inspect or move the existing path manually before running without --dry-run', output)
            self.assertFalse((container_dir / 'client-safe' / 'sh-7f3a9c21.hc').exists())
            self.assertEqual((blocked_mount / 'foreign.txt').read_text(encoding='utf-8'), 'keep-me\n')
            self.assertEqual(safehouse.StateStore(paths).records(), [])

    def test_new_engagement_dry_run_previews_without_password_backend_or_writes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            container_dir = Path(td) / 'containers'
            defaults_result = self.run_cli_with_home(
                home,
                'defaults',
                'set', 'engagement', '--path', str(container_dir),
            )

            result = self.run_cli_with_home(home, 'new', '--dry-run', 'engagement', 'Client Safe')

            self.assertEqual(defaults_result.returncode, 0, defaults_result.stderr)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('DRY-RUN safehouse new engagement Client Safe', result.stdout)
            self.assertRegex(result.stdout, rf'Container path: {container_dir}/client-safe/sh-[0-9a-f]{{8}}\.hc')
            self.assertIn(f'Mount path: {container_dir}/client-safe/mount', result.stdout)
            self.assertIn('Would prompt for VeraCrypt password: yes', result.stdout)
            self.assertIn('Would create VeraCrypt container', result.stdout)
            self.assertIn('Would mount VeraCrypt container', result.stdout)
            self.assertIn('Obsidian profile: minimal', result.stdout)
            self.assertNotIn('secret-passphrase', result.stdout + result.stderr)
            self.assertFalse(container_dir.exists())
            self.assertEqual(safehouse.StateStore(safehouse.AppPaths.from_home(home)).records(), [])

    def test_new_engagement_refuses_non_tty_password_input_before_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            container_dir = Path(td) / 'containers'
            defaults_result = self.run_cli_with_home(
                home,
                'defaults',
                'set', 'engagement', '--path', str(container_dir),
            )
            result = self.run_cli_with_home(
                home,
                'new', 'engagement', 'Client Safe',
                input_text='secret-passphrase\nsecret-passphrase\n',
                extra_env={'SAFEHOUSE_BACKEND': 'fake'},
            )

            self.assertEqual(defaults_result.returncode, 0, defaults_result.stderr)
            self.assertEqual(result.returncode, 2)
            self.assertIn('interactive terminal', result.stderr)
            self.assertEqual(safehouse.StateStore(safehouse.AppPaths.from_home(home)).records(), [])
            self.assertFalse(container_dir.exists())
            self.assertNotIn('secret-passphrase', result.stdout + result.stderr)

    def test_new_password_refuses_mismatched_tty_confirmation(self) -> None:
        values = iter(['first-passphrase', 'second-passphrase'])

        with mock.patch('safehouse.sys.stdin.isatty', return_value=True), \
            mock.patch('safehouse.getpass.getpass', side_effect=lambda prompt: next(values)):
            with self.assertRaisesRegex(ValueError, 'confirmation did not match'):
                safehouse.read_new_password()

    def test_list_cli_reports_empty_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            result = self.run_cli_with_home(home, 'list')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('No Safehouses yet.', result.stdout)
            self.assertIn('safehouse new lab "Dogfood Lab"', result.stdout)
            self.assertIn('safehouse new engagement "Client Name"', result.stdout)
            self.assertNotIn(str(home), result.stdout)
            self.assertNotIn('registry', result.stdout)
            self.assertNotIn('scan', result.stdout)
            self.assertNotIn('adopt', result.stdout)

    def test_list_cli_json_reports_scriptable_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111',
                display_name='Odyssey',
                slug='odyssey',
                category='lab',
                storage='plain',
                container_path='',
                mount_path=str(Path(td) / 'labs' / 'odyssey'),
                size='',
                filesystem='',
                phase='ready',
                created_at='2026-09-01T10:00:00+00:00',
            ))
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-22222222',
                display_name='Client Safe',
                slug='client-safe',
                category='engagement',
                storage='encrypted',
                container_path=str(Path(td) / 'containers' / 'sh-22222222.hc'),
                mount_path=str(Path(td) / 'mounts' / 'sh-22222222'),
                size='512M',
                filesystem='ext4',
                phase='closed',
                created_at='2026-09-01T11:00:00+00:00',
            ))

            result = self.run_cli_with_home(home, 'list', '--json')

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload['count'], 2)
            by_id = {item['safehouse_id']: item for item in payload['safehouses']}
            self.assertEqual([item['safehouse_id'] for item in payload['safehouses']], ['sh-22222222', 'sh-11111111'])
            self.assertEqual(by_id['sh-11111111']['safehouse_path'], str(Path(td) / 'labs' / 'odyssey'))
            self.assertEqual(by_id['sh-22222222']['safehouse_path'], str(Path(td) / 'mounts' / 'sh-22222222'))
            self.assertNotIn('path', by_id['sh-11111111'])
            self.assertNotIn('password', result.stdout.lower())
            self.assertNotIn('secret', result.stdout.lower())

    def test_list_cli_prints_compact_registry_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111',
                display_name='Odyssey',
                slug='odyssey',
                category='lab',
                storage='plain',
                container_path='',
                mount_path=str(Path(td) / 'labs' / 'odyssey'),
                size='',
                filesystem='',
                phase='ready',
                created_at='2026-09-01T10:00:00+00:00',
            ))
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-22222222',
                display_name='Client Safe',
                slug='client-safe',
                category='engagement',
                storage='encrypted',
                container_path=str(Path(td) / 'containers' / 'sh-22222222.hc'),
                mount_path=str(Path(td) / 'mounts' / 'sh-22222222'),
                size='512M',
                filesystem='ext4',
                phase='closed',
                created_at='2026-09-01T11:00:00+00:00',
            ))

            result = self.run_cli_with_home(home, 'list')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('ID          CATEGORY    STORAGE    PHASE   NAME         PATH', result.stdout)
            self.assertIn('sh-11111111 lab         plain      ready   Odyssey', result.stdout)
            self.assertIn('sh-22222222 engagement  encrypted  closed  Client Safe', result.stdout)
            self.assertIn(str(Path(td) / 'labs' / 'odyssey'), result.stdout)
            self.assertIn(str(Path(td) / 'mounts' / 'sh-22222222'), result.stdout)

    def test_list_cli_filters_by_safehouse_category(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Odyssey', slug='odyssey', category='lab', storage='plain',
                container_path='', mount_path=str(Path(td) / 'labs' / 'odyssey'), size='', filesystem='', phase='ready',
            ))
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-22222222', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(Path(td) / 'containers' / 'sh-22222222.hc'), mount_path=str(Path(td) / 'mounts' / 'sh-22222222'), size='512M', filesystem='ext4', phase='closed',
            ))

            labs = self.run_cli_with_home(home, 'list', '--lab')
            engagements = self.run_cli_with_home(home, 'list', '--engagement')
            json_labs = self.run_cli_with_home(home, 'list', '--lab', '--json')

            self.assertEqual(labs.returncode, 0, labs.stderr)
            self.assertIn('Odyssey', labs.stdout)
            self.assertNotIn('Client Safe', labs.stdout)
            self.assertEqual(engagements.returncode, 0, engagements.stderr)
            self.assertIn('Client Safe', engagements.stdout)
            self.assertNotIn('Odyssey', engagements.stdout)
            self.assertEqual(json_labs.returncode, 0, json_labs.stderr)
            payload = json.loads(json_labs.stdout)
            self.assertEqual(payload['count'], 1)
            self.assertEqual(payload['safehouses'][0]['category'], 'lab')

    def test_status_cli_reports_empty_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = self.run_cli_with_home(Path(td) / 'home', 'status')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('No Safehouses yet.', result.stdout)

    def test_status_cli_json_reports_scriptable_health_and_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            lab_path = Path(td) / 'labs' / 'odyssey'
            stale_container = Path(td) / 'containers' / 'sh-33333333.hc'
            missing_lab_path = Path(td) / 'labs' / 'missing-lab'
            lab_path.mkdir(parents=True)
            stale_container.parent.mkdir(parents=True)
            stale_container.write_text('fake volume', encoding='utf-8')
            for record in [
                safehouse.SafehouseRecord(
                    safehouse_id='sh-11111111', display_name='Odyssey', slug='odyssey', category='lab', storage='plain',
                    container_path='', mount_path=str(lab_path), size='', filesystem='', phase='ready',
                ),
                safehouse.SafehouseRecord(
                    safehouse_id='sh-33333333', display_name='Stale Client', slug='stale-client', category='engagement', storage='encrypted',
                    container_path=str(stale_container), mount_path=str(Path(td) / 'mounts' / 'sh-33333333'), size='512M', filesystem='ext4', phase='ready',
                ),
                safehouse.SafehouseRecord(
                    safehouse_id='sh-66666666', display_name='Missing Lab', slug='missing-lab', category='lab', storage='plain',
                    container_path='', mount_path=str(missing_lab_path), size='', filesystem='', phase='ready',
                ),
            ]:
                state.upsert(record)

            result = self.run_cli_with_home(home, 'status', '--json')

            self.assertEqual(result.returncode, 1, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload['exit_code'], 1)
            self.assertEqual(payload['count'], 3)
            by_id = {item['safehouse_id']: item for item in payload['safehouses']}
            self.assertEqual(by_id['sh-11111111']['status'], 'READY')
            self.assertEqual(by_id['sh-11111111']['safehouse_path'], str(lab_path))
            self.assertEqual(by_id['sh-33333333']['status'], 'STALE_STATE')
            self.assertEqual(by_id['sh-33333333']['safehouse_path'], str(Path(td) / 'mounts' / 'sh-33333333'))
            self.assertNotIn('path', by_id['sh-33333333'])
            self.assertIn('registry says ready but mount is not present', by_id['sh-33333333']['warning'])
            self.assertIn('run veracrypt -t --list', by_id['sh-33333333']['next'])
            self.assertEqual(by_id['sh-66666666']['status'], 'MISSING')
            self.assertNotIn('password', result.stdout.lower())
            self.assertNotIn('secret', result.stdout.lower())

    def test_status_cli_reconciles_registry_with_filesystem_reality(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            lab_path = Path(td) / 'labs' / 'odyssey'
            mounted_path = Path(td) / 'mounts' / 'sh-22222222'
            stale_mount_path = Path(td) / 'mounts' / 'sh-33333333'
            closed_mount_path = Path(td) / 'mounts' / 'sh-44444444'
            missing_lab_path = Path(td) / 'labs' / 'missing-lab'
            mounted_container = Path(td) / 'containers' / 'sh-22222222.hc'
            stale_container = Path(td) / 'containers' / 'sh-33333333.hc'
            closed_container = Path(td) / 'containers' / 'sh-44444444.hc'
            missing_container = Path(td) / 'containers' / 'sh-55555555.hc'
            lab_path.mkdir(parents=True)
            mounted_path.mkdir(parents=True)
            (mounted_path / '00_run.md').write_text('# mounted\n', encoding='utf-8')
            (mounted_path / '00_access.md').write_text('# access\n', encoding='utf-8')
            mounted_container.parent.mkdir(parents=True)
            mounted_container.write_text('fake volume', encoding='utf-8')
            stale_container.write_text('fake volume', encoding='utf-8')
            closed_container.write_text('fake volume', encoding='utf-8')
            for record in [
                safehouse.SafehouseRecord(
                    safehouse_id='sh-11111111', display_name='Odyssey', slug='odyssey', category='lab', storage='plain',
                    container_path='', mount_path=str(lab_path), size='', filesystem='', phase='ready',
                ),
                safehouse.SafehouseRecord(
                    safehouse_id='sh-22222222', display_name='Mounted Client', slug='mounted-client', category='engagement', storage='encrypted',
                    container_path=str(mounted_container), mount_path=str(mounted_path), size='512M', filesystem='ext4', phase='ready',
                ),
                safehouse.SafehouseRecord(
                    safehouse_id='sh-33333333', display_name='Stale Client', slug='stale-client', category='engagement', storage='encrypted',
                    container_path=str(stale_container), mount_path=str(stale_mount_path), size='512M', filesystem='ext4', phase='ready',
                ),
                safehouse.SafehouseRecord(
                    safehouse_id='sh-44444444', display_name='Closed Client', slug='closed-client', category='engagement', storage='encrypted',
                    container_path=str(closed_container), mount_path=str(closed_mount_path), size='512M', filesystem='ext4', phase='closed',
                ),
                safehouse.SafehouseRecord(
                    safehouse_id='sh-55555555', display_name='Broken Client', slug='broken-client', category='engagement', storage='encrypted',
                    container_path=str(missing_container), mount_path=str(Path(td) / 'mounts' / 'sh-55555555'), size='512M', filesystem='ext4', phase='ready',
                ),
                safehouse.SafehouseRecord(
                    safehouse_id='sh-66666666', display_name='Missing Lab', slug='missing-lab', category='lab', storage='plain',
                    container_path='', mount_path=str(missing_lab_path), size='', filesystem='', phase='ready',
                ),
            ]:
                state.upsert(record)

            result = self.run_cli_with_home(home, 'status')

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('STATUS          ID          CATEGORY    STORAGE    PHASE   NAME', result.stdout)
            self.assertIn('MOUNTED         sh-22222222 engagement  encrypted  ready   Mounted Client', result.stdout)
            self.assertIn('READY           sh-11111111 lab         plain      ready   Odyssey', result.stdout)
            self.assertIn('CLOSED          sh-44444444 engagement  encrypted  closed  Closed Client', result.stdout)
            self.assertIn('STALE_STATE     sh-33333333 engagement  encrypted  ready   Stale Client', result.stdout)
            self.assertIn('MISSING         sh-66666666 lab         plain      ready   Missing Lab', result.stdout)
            self.assertIn('NEEDS_RECOVERY  sh-55555555 engagement  encrypted  ready   Broken Client', result.stdout)
            self.assertLess(result.stdout.index('MOUNTED'), result.stdout.index('CLOSED'))
            self.assertIn('WARN sh-33333333 registry says ready but mount is not present', result.stdout)
            self.assertIn('WARN sh-55555555 missing container', result.stdout)

    def test_status_cli_filters_by_safehouse_category(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            lab_path = Path(td) / 'labs' / 'odyssey'
            lab_path.mkdir(parents=True)
            container = Path(td) / 'containers' / 'sh-22222222.hc'
            container.parent.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Odyssey', slug='odyssey', category='lab', storage='plain',
                container_path='', mount_path=str(lab_path), size='', filesystem='', phase='ready',
            ))
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-22222222', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(Path(td) / 'mounts' / 'sh-22222222'), size='512M', filesystem='ext4', phase='closed',
            ))

            labs = self.run_cli_with_home(home, 'status', '--lab')
            engagements = self.run_cli_with_home(home, 'status', '--engagement')
            json_engagements = self.run_cli_with_home(home, 'status', '--engagement', '--json')

            self.assertEqual(labs.returncode, 0, labs.stderr)
            self.assertIn('Odyssey', labs.stdout)
            self.assertNotIn('Client Safe', labs.stdout)
            self.assertEqual(engagements.returncode, 0, engagements.stderr)
            self.assertIn('Client Safe', engagements.stdout)
            self.assertNotIn('Odyssey', engagements.stdout)
            self.assertEqual(json_engagements.returncode, 0, json_engagements.stderr)
            payload = json.loads(json_engagements.stdout)
            self.assertEqual(payload['count'], 1)
            self.assertEqual(payload['safehouses'][0]['category'], 'engagement')

    def test_unmount_safehouse_marks_encrypted_record_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            state = safehouse.StateStore(paths)
            backend = safehouse.FakeVeraCryptBackend()
            container = Path(td) / 'containers' / 'sh-7f3a9c21.hc'
            mount = Path(td) / 'mounts' / 'sh-7f3a9c21'
            backend.create_volume(container, size='512M', filesystem='ext4', password='secret')
            backend.mount_volume(container, mount, password='secret')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-7f3a9c21',
                display_name='Client Safe Name',
                slug='client-safe-name',
                category='engagement',
                storage='encrypted',
                container_path=str(container),
                mount_path=str(mount),
                size='512M',
                filesystem='ext4',
                phase='ready',
            ))

            closed = safehouse.unmount_safehouse(state, backend, 'client-safe-name')

            self.assertEqual(closed.safehouse_id, 'sh-7f3a9c21')
            self.assertEqual(backend.mounted(), {})
            self.assertEqual(state.records()[0].phase, 'closed')

    def test_unmount_cli_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            container = Path(td) / 'containers' / 'sh-7f3a9c21.hc'
            mount = Path(td) / 'mounts' / 'sh-7f3a9c21'
            container.parent.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            mount.mkdir(parents=True)
            (mount / '00_run.md').write_text('# run\n', encoding='utf-8')
            (mount / '00_access.md').write_text('# access\n', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-7f3a9c21', display_name='Client Safe Name', slug='client-safe-name', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='ready',
            ))

            unmount_result = self.run_cli_with_home(home, 'unmount', 'Client Safe Name', extra_env={'SAFEHOUSE_BACKEND': 'fake'})
            force_result = self.run_cli_with_home(home, 'unmount', 'Client Safe Name', '--force', extra_env={'SAFEHOUSE_BACKEND': 'fake'})

            self.assertEqual(unmount_result.returncode, 0, unmount_result.stderr)
            self.assertIn('unmounted sh-7f3a9c21 Client Safe Name', unmount_result.stdout)
            self.assertEqual(safehouse.StateStore(paths).records()[0].phase, 'closed')
            self.assertNotEqual(force_result.returncode, 0)
            self.assertIn('unrecognized arguments: --force', force_result.stderr)

    def test_native_backend_refreshes_sudo_credentials_before_unmount(self) -> None:
        events: list[str] = []
        backend = safehouse.VeraCryptAdapter(command='veracrypt', runner=lambda call: 'ok')

        def fake_refresh(candidate: object) -> None:
            self.assertIs(candidate, backend)
            events.append('sudo')

        def fake_unmount(state: safehouse.StateStore, candidate: object, selector: str) -> safehouse.SafehouseRecord:
            self.assertIsInstance(state, safehouse.StateStore)
            self.assertIs(candidate, backend)
            self.assertEqual(selector, 'Client Safe')
            events.append('unmount')
            return safehouse.SafehouseRecord(
                safehouse_id='sh-7f3a9c21', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path='/safehouse/client-safe/sh-7f3a9c21.hc', mount_path='/safehouse/client-safe/mount', size='512M', filesystem='ext4', phase='closed',
            )

        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {'SAFEHOUSE_HOME': str(Path(td) / 'home')}, clear=False), \
                mock.patch('safehouse.backend_from_env', return_value=backend), \
                mock.patch('safehouse.refresh_admin_credentials_for_backend', fake_refresh), \
                mock.patch('safehouse.unmount_safehouse', fake_unmount):
                exit_code = safehouse.main(['unmount', 'Client Safe'])

        self.assertEqual(exit_code, 0)
        self.assertEqual(events, ['sudo', 'unmount'])

    def test_unmount_ctrl_c_during_sudo_refresh_exits_without_traceback(self) -> None:
        backend = safehouse.VeraCryptAdapter(command='veracrypt', runner=lambda call: 'ok')
        stderr = io.StringIO()

        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {'SAFEHOUSE_HOME': str(Path(td) / 'home')}, clear=False), \
                mock.patch('safehouse.backend_from_env', return_value=backend), \
                mock.patch('safehouse.refresh_admin_credentials_for_backend', side_effect=KeyboardInterrupt), \
                contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    safehouse.main(['unmount', 'Client Safe'])

        self.assertEqual(caught.exception.code, 130)
        self.assertEqual(stderr.getvalue(), 'safehouse: interrupted\n')

    def test_unmount_refuses_plain_labs_and_unknown_selectors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = safehouse.StateStore(safehouse.AppPaths.from_home(Path(td) / 'home'))
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Odyssey', slug='odyssey', category='lab', storage='plain',
                container_path='', mount_path=str(Path(td) / 'labs' / 'odyssey'), size='', filesystem='', phase='ready',
            ))

            with self.assertRaises(RuntimeError) as lab_error:
                safehouse.unmount_safehouse(state, safehouse.FakeVeraCryptBackend(), 'Odyssey')
            with self.assertRaises(RuntimeError) as missing_error:
                safehouse.unmount_safehouse(state, safehouse.FakeVeraCryptBackend(), 'missing')

            self.assertIn('plain lab has no VeraCrypt mount to unmount', str(lab_error.exception))
            self.assertIn('unknown safehouse selector: missing', str(missing_error.exception))

    def test_mount_safehouse_marks_encrypted_record_ready(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            state = safehouse.StateStore(paths)
            backend = safehouse.FakeVeraCryptBackend()
            container = Path(td) / 'containers' / 'sh-7f3a9c21.hc'
            mount = Path(td) / 'mounts' / 'sh-7f3a9c21'
            backend.create_volume(container, size='512M', filesystem='ext4', password='secret')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-7f3a9c21',
                display_name='Client Safe Name',
                slug='client-safe-name',
                category='engagement',
                storage='encrypted',
                container_path=str(container),
                mount_path=str(mount),
                size='512M',
                filesystem='ext4',
                phase='closed',
            ))

            opened = safehouse.mount_safehouse(state, backend, 'sh-7f3a9c21', 'secret-passphrase')

            self.assertEqual(opened.safehouse_id, 'sh-7f3a9c21')
            self.assertEqual(backend.mounted(), {container: mount})
            records = state.records()
            self.assertEqual(records[0].phase, 'ready')
            self.assertNotEqual(records[0].last_opened_at, '')
            self.assertNotIn('secret-passphrase', paths.state_file.read_text(encoding='utf-8'))

    def test_mount_cli_without_legacy_open_alias_or_secret_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            container = Path(td) / 'containers' / 'sh-7f3a9c21.hc'
            mount = Path(td) / 'mounts' / 'sh-7f3a9c21'
            container.parent.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-7f3a9c21', display_name='Client Safe Name', slug='client-safe-name', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            mount_result = self.run_tty_cli_with_home(
                home,
                'mount', 'Client Safe Name',
                password_values=['secret-passphrase'],
                extra_env={'SAFEHOUSE_BACKEND': 'fake'},
            )
            self.assertEqual(mount_result.returncode, 0, mount_result.stderr)
            self.assertIn('mounted sh-7f3a9c21 Client Safe Name', mount_result.stdout)
            self.assertIn(str(mount), mount_result.stdout)
            self.assertNotIn('secret-passphrase', mount_result.stdout + mount_result.stderr)
            self.assertEqual(safehouse.StateStore(paths).records()[0].phase, 'ready')

    def test_mount_refuses_plain_labs_and_missing_containers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = safehouse.StateStore(safehouse.AppPaths.from_home(Path(td) / 'home'))
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Odyssey', slug='odyssey', category='lab', storage='plain',
                container_path='', mount_path=str(Path(td) / 'labs' / 'odyssey'), size='', filesystem='', phase='ready',
            ))
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-22222222', display_name='Broken Client', slug='broken-client', category='engagement', storage='encrypted',
                container_path=str(Path(td) / 'containers' / 'sh-22222222.hc'), mount_path=str(Path(td) / 'mounts' / 'sh-22222222'), size='512M', filesystem='ext4', phase='closed',
            ))

            with self.assertRaises(RuntimeError) as lab_error:
                safehouse.mount_safehouse(state, safehouse.FakeVeraCryptBackend(), 'Odyssey', 'secret')
            with self.assertRaises(RuntimeError) as missing_error:
                safehouse.mount_safehouse(state, safehouse.FakeVeraCryptBackend(), 'Broken Client', 'secret')

            self.assertIn('plain lab does not need VeraCrypt mounting', str(lab_error.exception))
            self.assertIn('missing container', str(missing_error.exception))

    def test_mount_refuses_known_mounted_and_external_mount_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = safehouse.StateStore(safehouse.AppPaths.from_home(Path(td) / 'home'))
            mounted_container = Path(td) / 'containers' / 'sh-11111111.hc'
            mounted_path = Path(td) / 'mounts' / 'sh-11111111'
            blocked_container = Path(td) / 'containers' / 'sh-22222222.hc'
            blocked_path = Path(td) / 'mounts' / 'sh-22222222'
            mounted_container.parent.mkdir(parents=True)
            mounted_container.write_text('fake volume', encoding='utf-8')
            blocked_container.write_text('fake volume', encoding='utf-8')
            mounted_path.mkdir(parents=True)
            (mounted_path / '00_run.md').write_text('# run\n', encoding='utf-8')
            (mounted_path / '00_access.md').write_text('# access\n', encoding='utf-8')
            blocked_path.mkdir(parents=True)
            (blocked_path / 'someone-elses-file.txt').write_text('do not touch\n', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Mounted Client', slug='mounted-client', category='engagement', storage='encrypted',
                container_path=str(mounted_container), mount_path=str(mounted_path), size='512M', filesystem='ext4', phase='ready',
            ))
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-22222222', display_name='Blocked Client', slug='blocked-client', category='engagement', storage='encrypted',
                container_path=str(blocked_container), mount_path=str(blocked_path), size='512M', filesystem='ext4', phase='closed',
            ))

            with self.assertRaises(RuntimeError) as already_mounted:
                safehouse.mount_safehouse(state, safehouse.FakeVeraCryptBackend(), 'Mounted Client', 'secret')
            with self.assertRaises(RuntimeError) as blocked:
                safehouse.mount_safehouse(state, safehouse.FakeVeraCryptBackend(), 'Blocked Client', 'secret')

            self.assertIn('already appears mounted', str(already_mounted.exception))
            self.assertIn('safehouse status', str(already_mounted.exception))
            self.assertIn('refusing unknown/external mount path contents', str(blocked.exception))
            self.assertIn(str(blocked_path), str(blocked.exception))

    def test_status_reports_blocked_mount_path_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = safehouse.StateStore(safehouse.AppPaths.from_home(Path(td) / 'home'))
            container = Path(td) / 'containers' / 'sh-22222222.hc'
            mount = Path(td) / 'mounts' / 'sh-22222222'
            container.parent.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            mount.mkdir(parents=True)
            (mount / 'foreign.txt').write_text('external data\n', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-22222222', display_name='Blocked Client', slug='blocked-client', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            exit_code, lines = safehouse.format_status(state.records())

            self.assertEqual(exit_code, 1)
            rendered = '\n'.join(lines)
            self.assertIn('MOUNT_BLOCKED', rendered)
            self.assertIn('WARN sh-22222222 mount path contains unknown/external files', rendered)
            self.assertIn('NEXT sh-22222222 inspect mount path before moving anything', rendered)

    def test_status_prints_recovery_next_steps_for_problem_states(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing_lab = Path(td) / 'labs' / 'missing-lab'
            stale_container = Path(td) / 'containers' / 'sh-22222222.hc'
            stale_mount = Path(td) / 'mounts' / 'sh-22222222'
            missing_container = Path(td) / 'containers' / 'sh-33333333.hc'
            missing_container_mount = Path(td) / 'mounts' / 'sh-33333333'
            stale_container.parent.mkdir(parents=True)
            stale_container.write_text('fake volume', encoding='utf-8')
            stale_mount.mkdir(parents=True)
            (stale_mount / '00_run.md').write_text('# run\n', encoding='utf-8')
            (stale_mount / '00_access.md').write_text('# access\n', encoding='utf-8')
            records = [
                safehouse.SafehouseRecord(
                    safehouse_id='sh-11111111', display_name='Missing Lab', slug='missing-lab', category='lab', storage='plain',
                    container_path='', mount_path=str(missing_lab), size='', filesystem='', phase='ready',
                ),
                safehouse.SafehouseRecord(
                    safehouse_id='sh-22222222', display_name='Stale Client', slug='stale-client', category='engagement', storage='encrypted',
                    container_path=str(stale_container), mount_path=str(stale_mount), size='512M', filesystem='ext4', phase='ready',
                ),
                safehouse.SafehouseRecord(
                    safehouse_id='sh-33333333', display_name='Lost Container', slug='lost-container', category='engagement', storage='encrypted',
                    container_path=str(missing_container), mount_path=str(missing_container_mount), size='512M', filesystem='ext4', phase='closed',
                ),
            ]

            exit_code, lines = safehouse.format_status(records, live_mounts={})

            rendered = '\n'.join(lines)
            self.assertEqual(exit_code, 1)
            self.assertIn('NEXT sh-11111111 inspect or restore lab Safehouse', rendered)
            self.assertIn('NEXT sh-22222222 run veracrypt -t --list', rendered)
            self.assertIn('NEXT sh-33333333 inspect state, backups, or category path before editing state', rendered)

    def test_mount_collision_errors_include_non_destructive_recovery_step(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = safehouse.StateStore(safehouse.AppPaths.from_home(Path(td) / 'home'))
            container = Path(td) / 'containers' / 'sh-11111111.hc'
            mount = Path(td) / 'mounts' / 'sh-11111111'
            container.parent.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            mount.mkdir(parents=True)
            (mount / 'foreign.txt').write_text('external data\n', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Blocked Client', slug='blocked-client', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            with self.assertRaises(RuntimeError) as caught:
                safehouse.mount_safehouse(state, safehouse.FakeVeraCryptBackend(), 'Blocked Client', 'secret')

            message = str(caught.exception)
            self.assertIn('do not delete anything automatically', message)
            self.assertIn('inspect or move it manually', message)

    def test_veracrypt_list_parser_handles_native_text_formats(self) -> None:
        output = '''
Slot: 1
Volume: /vault/containers/sh-11111111.hc
Virtual Device: /dev/mapper/veracrypt1
Mount Directory: /mnt/safehouse/sh-11111111

2: /dev/mapper/veracrypt2 /vault/containers/sh-22222222.hc /mnt/safehouse/sh-22222222
3: /vault/containers/sh-33333333.hc /dev/mapper/veracrypt3 -
'''

        mounted = safehouse.parse_veracrypt_mounts(output)

        self.assertEqual(mounted[Path('/vault/containers/sh-11111111.hc')], Path('/mnt/safehouse/sh-11111111'))
        self.assertEqual(mounted[Path('/vault/containers/sh-22222222.hc')], Path('/mnt/safehouse/sh-22222222'))
        self.assertEqual(mounted[Path('/vault/containers/sh-33333333.hc')], Path('-'))

    def test_status_prefers_live_veracrypt_mounts_over_scaffold_guess(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            container = Path(td) / 'containers' / 'sh-11111111.hc'
            mount = Path(td) / 'mounts' / 'sh-11111111'
            container.parent.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            mount.mkdir(parents=True)
            (mount / '00_run.md').write_text('# run\n', encoding='utf-8')
            (mount / '00_access.md').write_text('# access\n', encoding='utf-8')
            record = safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='ready',
            )

            stale_code, stale_lines = safehouse.format_status([record], live_mounts={})
            mounted_code, mounted_lines = safehouse.format_status([record], live_mounts={container: mount})

            self.assertEqual(stale_code, 1)
            self.assertIn('STALE_STATE', '\n'.join(stale_lines))
            self.assertEqual(mounted_code, 0)
            self.assertIn('MOUNTED', '\n'.join(mounted_lines))

    def test_mount_refuses_already_mounted_from_live_veracrypt_list(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = safehouse.StateStore(safehouse.AppPaths.from_home(Path(td) / 'home'))
            container = Path(td) / 'containers' / 'sh-11111111.hc'
            mount = Path(td) / 'mounts' / 'sh-11111111'
            container.parent.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            mount.mkdir(parents=True)
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            with self.assertRaises(RuntimeError) as caught:
                safehouse.mount_safehouse(state, safehouse.FakeVeraCryptBackend(), 'Client Safe', 'secret', live_mounts={container: mount})

            self.assertIn('already appears mounted', str(caught.exception))

    def test_mount_cli_checks_existing_mount_before_password_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            container_dir = Path(td) / 'containers'
            mount_dir = Path(td) / 'mounts'
            fake_env = {'SAFEHOUSE_BACKEND': 'fake'}
            defaults_result = self.run_cli_with_home(home, 'defaults', 'set', 'engagement', '--path', str(container_dir))
            size_result = self.run_cli_with_home(home, 'defaults', 'set', 'engagement', '--container-size', '512M')
            new_result = self.run_tty_cli_with_home(home, 'new', 'engagement', 'Mounted Client', password_values=['secret', 'secret'], extra_env=fake_env)

            result = self.run_cli_with_home(home, 'mount', 'Mounted Client', input_text='', extra_env=fake_env)

            self.assertEqual(defaults_result.returncode, 0, defaults_result.stderr)
            self.assertEqual(size_result.returncode, 0, size_result.stderr)
            self.assertEqual(new_result.returncode, 0, new_result.stderr)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('already appears mounted', result.stderr)
            self.assertNotIn('VeraCrypt input must not be empty', result.stderr)

    def test_create_safehouse_refuses_external_mount_collision_without_deleting_container(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            container_dir = Path(td) / 'containers'
            colliding_mount = container_dir / 'collision-client' / 'mount'
            paths = safehouse.AppPaths.from_home(home)
            config = safehouse.ConfigStore(paths)
            state = safehouse.StateStore(paths)
            backend = safehouse.FakeVeraCryptBackend()
            config.set_category_default('engagement', 'path', str(container_dir))
            config.set_category_default('engagement', 'container-size', '512M')
            config.set_category_default('engagement', 'obsidian-profile', 'minimal')
            colliding_mount.mkdir(parents=True)
            (colliding_mount / 'foreign.txt').write_text('external data\n', encoding='utf-8')

            with self.assertRaises(RuntimeError) as caught:
                safehouse.create_safehouse(
                    category='engagement',
                    name='Collision Client',
                    config=config,
                    state=state,
                    backend=backend,
                    password='secret-passphrase',
                    id_rng=lambda n: b'\x7f:\x9c!',
                )

            self.assertIn('refusing unknown/external mount path contents', str(caught.exception))
            self.assertFalse((container_dir / 'collision-client' / 'sh-7f3a9c21.hc').exists())
            self.assertTrue((colliding_mount / 'foreign.txt').is_file())
            self.assertEqual(state.records(), [])

    def test_state_store_records_non_secret_safehouse_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = safehouse.StateStore(safehouse.AppPaths.from_home(Path(td)))
            record = safehouse.SafehouseRecord(
                safehouse_id='sh-7f3a9c21',
                display_name='Client Safe Name',
                slug='client-safe-name',
                category='engagement',
                container_path='/safehouse/containers/sh-7f3a9c21.hc',
                mount_path='/safehouse/mounts/sh-7f3a9c21',
                size='512M',
                filesystem='ext4',
                phase='creating',
            )

            store.upsert(record)

            records = store.records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].safehouse_id, 'sh-7f3a9c21')
            self.assertEqual(records[0].display_name, 'Client Safe Name')
            self.assertNotIn('password', store.paths.state_file.read_text(encoding='utf-8').lower())

    def test_state_store_updates_existing_record_phase(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = safehouse.StateStore(safehouse.AppPaths.from_home(Path(td)))
            record = safehouse.SafehouseRecord(
                safehouse_id='sh-7f3a9c21',
                display_name='Client Safe Name',
                slug='client-safe-name',
                category='engagement',
                container_path='/safehouse/containers/sh-7f3a9c21.hc',
                mount_path='/safehouse/mounts/sh-7f3a9c21',
                size='512M',
                filesystem='ext4',
                phase='creating',
            )

            store.upsert(record)
            store.upsert(record.with_phase('ready'))

            records = store.records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].phase, 'ready')

    def test_state_store_rejects_invalid_phase_and_secret_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = safehouse.StateStore(safehouse.AppPaths.from_home(Path(td)))
            good = safehouse.SafehouseRecord(
                safehouse_id='sh-7f3a9c21',
                display_name='Client Safe Name',
                slug='client-safe-name',
                category='engagement',
                container_path='/safehouse/containers/sh-7f3a9c21.hc',
                mount_path='/safehouse/mounts/sh-7f3a9c21',
                size='512M',
                filesystem='ext4',
                phase='ready',
            )

            with self.assertRaises(ValueError):
                store.upsert(good.with_phase('maybe-mounted'))
            with self.assertRaises(ValueError):
                store.write_raw({'safehouses': [{**good.to_dict(), 'password': 'nope'}]})

    def test_state_file_uses_restrictive_permissions_and_refuses_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td))
            store = safehouse.StateStore(paths)
            record = safehouse.SafehouseRecord(
                safehouse_id='sh-7f3a9c21',
                display_name='Client Safe Name',
                slug='client-safe-name',
                category='engagement',
                container_path='/safehouse/containers/sh-7f3a9c21.hc',
                mount_path='/safehouse/mounts/sh-7f3a9c21',
                size='512M',
                filesystem='ext4',
                phase='ready',
            )

            store.upsert(record)
            self.assertEqual(stat.S_IMODE(paths.state_file.stat().st_mode), 0o600)

            paths.state_file.unlink()
            paths.state_file.symlink_to(Path(td) / 'elsewhere.json')
            with self.assertRaises(RuntimeError):
                store.upsert(record)

    def test_removed_setup_subcommand_is_not_available(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            removed_command = ''.join(('in', 'it'))
            result = self.run_cli_with_home(Path(td), removed_command, '--help')

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"invalid choice: '{removed_command}'", result.stderr)

    def test_doctor_reports_config_state_and_fake_veracrypt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            fake_veracrypt = Path(td) / 'veracrypt'
            fake_mkfs = Path(td) / 'mkfs.ext4'
            fake_veracrypt.write_text('#!/usr/bin/env bash\necho "VeraCrypt 1.26.7"\n', encoding='utf-8')
            fake_mkfs.write_text('#!/usr/bin/env bash\n[[ "$1" == "-V" ]] || exit 64\necho "mke2fs 1.47.0"\n', encoding='utf-8')
            fake_veracrypt.chmod(0o700)
            fake_mkfs.chmod(0o700)
            defaults_result = self.run_cli_with_home(
                home,
                'defaults',
                'set', 'engagement', '--path', str(Path(td) / 'containers'),
            )
            self.assertEqual(defaults_result.returncode, 0, defaults_result.stderr)
            env_home = os.environ.copy()
            env_home['SAFEHOUSE_HOME'] = str(home)
            env_home['SAFEHOUSE_VERACRYPT'] = str(fake_veracrypt)
            env_home['SAFEHOUSE_MKFS_EXT4'] = str(fake_mkfs)

            result = subprocess.run(
                [sys.executable, str(ROOT / 'safehouse.py'), 'doctor'],
                cwd=ROOT,
                env=env_home,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('OK config', result.stdout)
            self.assertIn('OK state', result.stdout)
            self.assertIn('OK veracrypt', result.stdout)
            self.assertIn('OK mkfs.ext4', result.stdout)
            self.assertIn('OK default engagement.obsidian-profile minimal', result.stdout)
            self.assertIn('OK default lab.obsidian-profile minimal', result.stdout)
            self.assertNotIn('real-smoke', result.stdout)

    def test_doctor_reports_builtin_default_paths_before_first_use(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = self.run_cli_with_home(Path(td), 'doctor')

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('OK default lab.path', result.stdout)
            self.assertIn('(will create on first use)', result.stdout)
            self.assertIn('FAIL veracrypt', result.stdout)

    def test_doctor_gives_veracrypt_install_next_step_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            defaults_result = self.run_cli_with_home(
                home,
                'defaults',
                'set', 'engagement', '--path', str(Path(td) / 'containers'),
            )
            self.assertEqual(defaults_result.returncode, 0, defaults_result.stderr)

            result = self.run_cli_with_home(
                home,
                'doctor',
                extra_env={'SAFEHOUSE_VERACRYPT': str(Path(td) / 'missing-veracrypt')},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('FAIL veracrypt not found', result.stdout)
            self.assertIn('NEXT install VeraCrypt or set SAFEHOUSE_VERACRYPT', result.stdout)

    def test_doctor_checks_mkfs_ext4_before_encrypted_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            fake_veracrypt = Path(td) / 'veracrypt'
            fake_veracrypt.write_text('#!/usr/bin/env bash\necho "VeraCrypt 1.26.7"\n', encoding='utf-8')
            fake_veracrypt.chmod(0o700)
            defaults_result = self.run_cli_with_home(
                home,
                'defaults',
                'set', 'engagement', '--path', str(Path(td) / 'containers'),
            )
            self.assertEqual(defaults_result.returncode, 0, defaults_result.stderr)

            result = self.run_cli_with_home(
                home,
                'doctor',
                extra_env={
                    'SAFEHOUSE_VERACRYPT': str(fake_veracrypt),
                    'SAFEHOUSE_MKFS_EXT4': str(Path(td) / 'missing-mkfs.ext4'),
                },
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('FAIL mkfs.ext4 not found', result.stdout)
            self.assertIn('NEXT install e2fsprogs or set SAFEHOUSE_MKFS_EXT4', result.stdout)

    def test_doctor_fails_when_configured_obsidian_profile_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            fake_veracrypt = Path(td) / 'veracrypt'
            fake_mkfs = Path(td) / 'mkfs.ext4'
            fake_veracrypt.write_text('#!/usr/bin/env bash\necho "VeraCrypt 1.26.7"\n', encoding='utf-8')
            fake_mkfs.write_text('#!/usr/bin/env bash\n[[ "$1" == "-V" ]] || exit 64\necho "mke2fs 1.47.0"\n', encoding='utf-8')
            fake_veracrypt.chmod(0o700)
            fake_mkfs.chmod(0o700)
            defaults_result = self.run_cli_with_home(
                home,
                'defaults',
                'set', 'engagement', '--path', str(Path(td) / 'containers'),
            )
            default_result = self.run_cli_with_home(home, 'defaults', 'set', 'engagement', '--obsidian-profile', 'ghost')
            self.assertEqual(defaults_result.returncode, 0, defaults_result.stderr)
            self.assertEqual(default_result.returncode, 0, default_result.stderr)

            result = self.run_cli_with_home(
                home,
                'doctor',
                extra_env={
                    'SAFEHOUSE_VERACRYPT': str(fake_veracrypt),
                    'SAFEHOUSE_MKFS_EXT4': str(fake_mkfs),
                },
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('FAIL default engagement.obsidian-profile ghost does not exist', result.stdout)
            self.assertIn('NEXT safehouse obsidian-profile import ghost --from SOURCE_PATH', result.stdout)

    def test_doctor_fails_when_configured_obsidian_profile_manifest_drifts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            fake_veracrypt = Path(td) / 'veracrypt'
            fake_mkfs = Path(td) / 'mkfs.ext4'
            source = Path(td) / 'vault'
            obsidian = source / '.obsidian'
            fake_veracrypt.write_text('#!/usr/bin/env bash\necho "VeraCrypt 1.26.7"\n', encoding='utf-8')
            fake_mkfs.write_text('#!/usr/bin/env bash\n[[ "$1" == "-V" ]] || exit 64\necho "mke2fs 1.47.0"\n', encoding='utf-8')
            fake_veracrypt.chmod(0o700)
            fake_mkfs.chmod(0o700)
            obsidian.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{"accentColor":"secret-blue"}\n', encoding='utf-8')
            defaults_result = self.run_cli_with_home(
                home,
                'defaults',
                'set', 'engagement', '--path', str(Path(td) / 'containers'),
            )
            default_result = self.run_cli_with_home(home, 'defaults', 'set', 'engagement', '--obsidian-profile', 'work')
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))
            profile = safehouse.AppPaths.from_home(home).profile_dir / 'work'
            (profile / 'app.json').write_text('{"accentColor":"changed-secret"}\n', encoding='utf-8')
            self.assertEqual(defaults_result.returncode, 0, defaults_result.stderr)
            self.assertEqual(default_result.returncode, 0, default_result.stderr)
            self.assertEqual(imported.returncode, 0, imported.stderr)

            result = self.run_cli_with_home(
                home,
                'doctor',
                extra_env={
                    'SAFEHOUSE_VERACRYPT': str(fake_veracrypt),
                    'SAFEHOUSE_MKFS_EXT4': str(fake_mkfs),
                },
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('FAIL default engagement.obsidian-profile work manifest drift', result.stdout)
            self.assertIn('FAIL hash mismatch: app.json', result.stdout)
            self.assertIn('NEXT safehouse obsidian-profile verify work', result.stdout)
            self.assertIn('NEXT re-import with `safehouse obsidian-profile replace work --from SOURCE`', result.stdout)
            self.assertNotIn('changed-secret', result.stdout)

    def test_doctor_json_reports_scriptable_checks_without_dumping_config(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            fake_veracrypt = Path(td) / 'veracrypt'
            fake_mkfs = Path(td) / 'mkfs.ext4'
            source = Path(td) / 'vault'
            obsidian = source / '.obsidian'
            fake_veracrypt.write_text('#!/usr/bin/env bash\necho "VeraCrypt 1.26.7"\n', encoding='utf-8')
            fake_mkfs.write_text('#!/usr/bin/env bash\n[[ "$1" == "-V" ]] || exit 64\necho "mke2fs 1.47.0"\n', encoding='utf-8')
            fake_veracrypt.chmod(0o700)
            fake_mkfs.chmod(0o700)
            obsidian.mkdir(parents=True)
            (obsidian / 'app.json').write_text('{"accentColor":"secret-blue"}\n', encoding='utf-8')
            defaults_result = self.run_cli_with_home(
                home,
                'defaults',
                'set', 'engagement', '--path', str(Path(td) / 'containers'),
            )
            default_result = self.run_cli_with_home(home, 'defaults', 'set', 'engagement', '--obsidian-profile', 'work')
            imported = self.run_cli_with_home(home, 'obsidian-profile', 'import', 'work', '--from', str(source))
            profile = safehouse.AppPaths.from_home(home).profile_dir / 'work'
            (profile / 'app.json').write_text('{"accentColor":"changed-secret"}\n', encoding='utf-8')
            self.assertEqual(defaults_result.returncode, 0, defaults_result.stderr)
            self.assertEqual(default_result.returncode, 0, default_result.stderr)
            self.assertEqual(imported.returncode, 0, imported.stderr)

            result = self.run_cli_with_home(
                home,
                'doctor',
                '--json',
                extra_env={
                    'SAFEHOUSE_VERACRYPT': str(fake_veracrypt),
                    'SAFEHOUSE_MKFS_EXT4': str(fake_mkfs),
                },
            )

            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertEqual(payload['exit_code'], 1)
            self.assertTrue(any(check['status'] == 'FAIL' and check['check'] == 'default' and 'engagement.obsidian-profile' in check['detail'] for check in payload['checks']))
            self.assertIn('safehouse obsidian-profile verify work', payload['next'])
            self.assertIn('re-import with `safehouse obsidian-profile replace work --from SOURCE`', payload['next'])
            self.assertNotIn('changed-secret', result.stdout)
            self.assertNotIn('secret-blue', result.stdout)

    @unittest.skipUnless(HAS_PRIVATE_RELEASE_TOOLING, 'private release tooling is not part of the public source tree')
    def test_real_veracrypt_smoke_runner_has_safe_help_and_dry_run(self) -> None:
        script = ROOT / 'scripts' / 'smoke-real-veracrypt'

        help_result = subprocess.run(
            [str(script), '--help'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        dry_run = subprocess.run(
            [str(script), '--dry-run'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn('disposable', help_result.stdout)
        self.assertIn('does not use real engagement data', help_result.stdout)
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertIn('mktemp', dry_run.stdout)
        self.assertIn('safehouse.py new engagement "Smoke Client"', dry_run.stdout)
        self.assertIn('safehouse.py unmount "Smoke Client"', dry_run.stdout)
        self.assertNotIn('rm -rf /vault', dry_run.stdout)

    @unittest.skipUnless(HAS_PRIVATE_RELEASE_TOOLING, 'private release tooling is not part of the public source tree')
    def test_real_veracrypt_smoke_runner_prints_safe_report_template(self) -> None:
        script = ROOT / 'scripts' / 'smoke-real-veracrypt'

        result = subprocess.run(
            [str(script), '--report-template'],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Safehouse real VeraCrypt smoke report', result.stdout)
        self.assertIn('Paste this safe summary back for review', result.stdout)
        self.assertIn('check-prereqs:', result.stdout)
        self.assertIn('dry-run:', result.stdout)
        self.assertIn('normal-run:', result.stdout)
        self.assertIn('final-status:', result.stdout)
        self.assertIn('veracrypt-list:', result.stdout)
        self.assertIn('Do not paste passphrases', result.stdout)
        self.assertNotIn('secret', result.stdout.lower())
        self.assertNotIn('password:', result.stdout.lower())

    @unittest.skipUnless(HAS_PRIVATE_RELEASE_TOOLING, 'private release tooling is not part of the public source tree')
    def test_real_veracrypt_smoke_runner_missing_veracrypt_fails_before_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            empty_path = Path(td) / 'empty-bin'
            empty_path.mkdir()
            env = os.environ.copy()
            env['PATH'] = str(empty_path)
            result = subprocess.run(
                [str(ROOT / 'scripts' / 'smoke-real-veracrypt'), '--check-prereqs'],
                cwd=ROOT,
                env=env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('VeraCrypt CLI not found', result.stderr)
            self.assertFalse((Path(td) / 'safehouse-smoke').exists())

    @unittest.skipUnless(HAS_PRIVATE_RELEASE_TOOLING, 'private release tooling is not part of the public source tree')
    def test_real_veracrypt_smoke_runner_reports_successful_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bin_dir = Path(td) / 'bin'
            bin_dir.mkdir()
            fake_veracrypt = bin_dir / 'veracrypt'
            fake_mkfs = bin_dir / 'mkfs.ext4'
            fake_veracrypt.write_text('#!/usr/bin/env bash\nexit 0\n', encoding='utf-8')
            fake_mkfs.write_text('#!/usr/bin/env bash\nexit 0\n', encoding='utf-8')
            fake_veracrypt.chmod(0o700)
            fake_mkfs.chmod(0o700)
            env = os.environ.copy()
            env.update({
                'PATH': f'{bin_dir}:{env["PATH"]}',
                'SAFEHOUSE_VERACRYPT': str(fake_veracrypt),
                'SAFEHOUSE_MKFS_EXT4': str(fake_mkfs),
            })

            result = subprocess.run(
                [str(ROOT / 'scripts' / 'smoke-real-veracrypt'), '--check-prereqs'],
                cwd=ROOT,
                env=env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Prerequisites passed:', result.stdout)
            self.assertIn('VeraCrypt CLI', result.stdout)

    @unittest.skipUnless(HAS_PRIVATE_RELEASE_TOOLING, 'private release tooling is not part of the public source tree')
    def test_real_veracrypt_smoke_runner_refuses_piped_secret_input(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bin_dir = Path(td) / 'bin'
            bin_dir.mkdir()
            fake_veracrypt = bin_dir / 'veracrypt'
            fake_mkfs = bin_dir / 'mkfs.ext4'
            fake_veracrypt.write_text(
                '#!/usr/bin/env bash\n'
                'if [[ "$1" == "--version" ]]; then echo "VeraCrypt 1.26.29"; exit 0; fi\n'
                'if [[ "$1" == "-t" && "$2" == "--list" ]]; then exit 0; fi\n'
                'echo "unexpected veracrypt args: $*" >&2\n'
                'exit 64\n',
                encoding='utf-8',
            )
            fake_mkfs.write_text(
                '#!/usr/bin/env bash\n'
                '[[ "$1" == "-V" ]] || exit 64\n'
                'echo "mke2fs 1.47.3"\n',
                encoding='utf-8',
            )
            fake_veracrypt.chmod(0o700)
            fake_mkfs.chmod(0o700)
            env = os.environ.copy()
            env.update({
                'PATH': f'{bin_dir}:{env.get("PATH", "")}',
                'SAFEHOUSE_BACKEND': 'fake',
                'SAFEHOUSE_VERACRYPT': str(fake_veracrypt),
                'SAFEHOUSE_MKFS_EXT4': str(fake_mkfs),
            })

            result = subprocess.run(
                [str(ROOT / 'scripts' / 'smoke-real-veracrypt')],
                cwd=ROOT,
                env=env,
                check=False,
                input='throwaway\nthrowaway\n',
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn('OK default engagement.path', result.stdout)
            self.assertIn('(will create on first use)', result.stdout)
            self.assertIn('container-size = 32M', result.stdout)
            self.assertIn('interactive terminal', result.stderr)

    def test_veracrypt_create_command_uses_boring_defaults_without_secret_argv(self) -> None:
        calls: list[safehouse.VeraCryptCall] = []
        adapter = safehouse.VeraCryptAdapter(command='veracrypt', runner=lambda call: calls.append(call) or 'created')

        adapter.create_volume(
            Path('/safehouse/containers/sh-7f3a9c21.hc'),
            size='512M',
            filesystem='ext4',
            password='super-secret-passphrase',
        )

        argv = calls[0].argv
        self.assertIn('-t', argv)
        self.assertIn('-c', argv)
        self.assertIn('--volume-type=normal', argv)
        self.assertIn('--encryption=AES', argv)
        self.assertIn('--hash=SHA-512', argv)
        self.assertIn('--filesystem=ext4', argv)
        self.assertIn('--size=512M', argv)
        self.assertNotIn('super-secret-passphrase', ' '.join(argv))
        self.assertNotIn('password', ' '.join(argv).lower())
        self.assertEqual(calls[0].stdin, 'super-secret-passphrase\n')
        self.assertNotIn('super-secret-passphrase', calls[0].safe_display())

    def test_veracrypt_mount_and_unmount_commands_do_not_log_secret(self) -> None:
        calls: list[safehouse.VeraCryptCall] = []
        adapter = safehouse.VeraCryptAdapter(command='veracrypt', runner=lambda call: calls.append(call) or '')

        adapter.mount_volume(
            Path('/safehouse/containers/sh-7f3a9c21.hc'),
            Path('/safehouse/mounts/sh-7f3a9c21'),
            password='super-secret-passphrase',
        )
        adapter.unmount(Path('/safehouse/mounts/sh-7f3a9c21'))

        mount_argv = calls[0].argv
        unmount_argv = calls[1].argv
        self.assertEqual(mount_argv[:2], ['veracrypt', '-t'])
        self.assertIn('--stdin', mount_argv)
        self.assertIn('--non-interactive', mount_argv)
        self.assertIn('--pim=0', mount_argv)
        self.assertIn('--protect-hidden=no', mount_argv)
        self.assertNotIn('super-secret-passphrase', ' '.join(mount_argv))
        self.assertEqual(calls[0].stdin, 'super-secret-passphrase\n')
        self.assertIn('--unmount', unmount_argv)
        self.assertIn('--non-interactive', unmount_argv)
        self.assertNotIn('--force', unmount_argv)

    def test_veracrypt_mount_creates_empty_mountpoint_for_native_cli(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            calls: list[safehouse.VeraCryptCall] = []
            adapter = safehouse.VeraCryptAdapter(command='veracrypt', runner=lambda call: calls.append(call) or '')
            container = Path(td) / 'containers' / 'sh-7f3a9c21.hc'
            mount = Path(td) / 'mounts' / 'sh-7f3a9c21'
            container.parent.mkdir(parents=True)
            container.write_text('fake container\n', encoding='utf-8')

            adapter.mount_volume(container, mount, password='super-secret-passphrase')

            self.assertTrue(mount.is_dir())
            self.assertEqual(stat.S_IMODE(mount.stat().st_mode), 0o700)
            self.assertEqual(calls[0].argv[2:4], [str(container), str(mount)])

    def test_veracrypt_mount_chowns_ext4_root_when_not_writable_by_user(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            calls: list[safehouse.VeraCryptCall] = []
            chowns: list[list[str]] = []
            adapter = safehouse.VeraCryptAdapter(command='veracrypt', runner=lambda call: calls.append(call) or '')
            container = Path(td) / 'containers' / 'sh-7f3a9c21.hc'
            mount = Path(td) / 'mounts' / 'sh-7f3a9c21'
            container.parent.mkdir(parents=True)
            container.write_text('fake container\n', encoding='utf-8')

            def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                del kwargs
                chowns.append(argv)
                return subprocess.CompletedProcess(args=argv, returncode=0, stdout='', stderr='')

            with mock.patch('safehouse.os.access', return_value=False), mock.patch('safehouse.subprocess.run', fake_run):
                adapter.mount_volume(container, mount, password='super-secret-passphrase')

            self.assertEqual(calls[0].argv[2:4], [str(container), str(mount)])
            self.assertEqual(chowns, [['sudo', '-n', 'chown', f'{os.getuid()}:{os.getgid()}', str(mount)]])

    def test_native_backend_refreshes_sudo_credentials_before_veracrypt_password_prompt(self) -> None:
        events: list[str] = []
        backend = safehouse.VeraCryptAdapter(command='veracrypt', runner=lambda call: 'ok')

        def fake_refresh(candidate: object) -> None:
            self.assertIs(candidate, backend)
            events.append('sudo')

        def fake_read_password() -> str:
            events.append('veracrypt-password')
            return 'super-secret-passphrase'

        def fake_create(**kwargs: object) -> safehouse.SafehousePaths:
            events.append('create')
            self.assertIs(kwargs['backend'], backend)
            self.assertEqual(kwargs['password'], 'super-secret-passphrase')
            return safehouse.SafehousePaths(
                display_name='Client Safe',
                slug='client-safe',
                safehouse_id='sh-7f3a9c21',
                container_path=Path('/safehouse/client-safe/sh-7f3a9c21.hc'),
                mount_path=Path('/safehouse/client-safe/mount'),
            )

        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {'SAFEHOUSE_HOME': str(Path(td) / 'home')}, clear=False), \
                mock.patch('safehouse.backend_from_env', return_value=backend), \
                mock.patch('safehouse.refresh_admin_credentials_for_backend', fake_refresh), \
                mock.patch('safehouse.read_new_password', fake_read_password), \
                mock.patch('safehouse.create_safehouse', fake_create):
                exit_code = safehouse.main(['new', 'engagement', 'Client Safe'])

        self.assertEqual(exit_code, 0)
        self.assertEqual(events, ['sudo', 'veracrypt-password', 'create'])

    def test_new_ctrl_c_during_sudo_refresh_exits_without_traceback_or_state(self) -> None:
        backend = safehouse.VeraCryptAdapter(command='veracrypt', runner=lambda call: 'ok')

        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            stderr = io.StringIO()
            with mock.patch.dict(os.environ, {'SAFEHOUSE_HOME': str(home)}, clear=False), \
                mock.patch('safehouse.backend_from_env', return_value=backend), \
                mock.patch('safehouse.refresh_admin_credentials_for_backend', side_effect=KeyboardInterrupt), \
                contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    safehouse.main(['new', 'engagement', 'Interrupted Client'])

            self.assertEqual(caught.exception.code, 130)
            self.assertEqual(stderr.getvalue(), 'safehouse: interrupted\n')
            self.assertFalse((home / '.config' / 'safehouse' / 'state.json').exists())

    def test_veracrypt_encryption_password_prompts_are_distinct_from_sudo(self) -> None:
        prompts: list[str] = []
        values = iter(['new-secret', 'new-secret', 'mount-secret'])

        def fake_getpass(prompt: str) -> str:
            prompts.append(prompt)
            return next(values)

        with mock.patch('safehouse.sys.stdin.isatty', return_value=True), mock.patch('safehouse.getpass.getpass', fake_getpass):
            self.assertEqual(safehouse.read_new_password(), 'new-secret')
            self.assertEqual(safehouse.read_mount_password(), 'mount-secret')

        self.assertEqual(prompts, [
            'VeraCrypt encryption password: ',
            'Confirm VeraCrypt encryption password: ',
            'VeraCrypt encryption password: ',
        ])

    def test_veracrypt_password_entry_refuses_non_tty_input(self) -> None:
        with mock.patch('safehouse.sys.stdin.isatty', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'interactive terminal'):
                safehouse.read_new_password()
            with self.assertRaisesRegex(RuntimeError, 'interactive terminal'):
                safehouse.read_mount_password()

    def test_sudo_refresh_uses_interactive_prompt_for_native_backend_only(self) -> None:
        calls: list[list[str]] = []

        def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            self.assertEqual(kwargs['check'], False)
            self.assertEqual(kwargs['timeout'], 120)
            self.assertNotIn('stdout', kwargs)
            self.assertNotIn('stderr', kwargs)
            return subprocess.CompletedProcess(args=argv, returncode=0)

        stderr = io.StringIO()
        with mock.patch('safehouse.os.getuid', return_value=1000), \
            mock.patch('safehouse.subprocess.run', fake_run), \
            contextlib.redirect_stderr(stderr):
            safehouse.refresh_admin_credentials_for_backend(safehouse.VeraCryptAdapter(command='veracrypt'))
            safehouse.refresh_admin_credentials_for_backend(safehouse.FakeVeraCryptBackend())

        self.assertEqual(calls, [['sudo', '-v']])
        self.assertIn('Enter your sudo password for this VeraCrypt operation.', stderr.getvalue())

    def test_veracrypt_create_creates_parent_directory_for_native_cli(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            calls: list[safehouse.VeraCryptCall] = []
            container = Path(td) / 'engagements' / 'client-safe' / 'sh-7f3a9c21.hc'

            def runner(call: safehouse.VeraCryptCall) -> str:
                calls.append(call)
                self.assertTrue(container.parent.is_dir())
                self.assertEqual(stat.S_IMODE(container.parent.stat().st_mode), 0o700)
                return 'created'

            adapter = safehouse.VeraCryptAdapter(command='veracrypt', runner=runner)

            adapter.create_volume(container, size='512M', filesystem='ext4', password='super-secret-passphrase')

            self.assertEqual(calls[0].argv[3], str(container))

    def test_fake_veracrypt_backend_tracks_lifecycle_without_real_mounts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            backend = safehouse.FakeVeraCryptBackend()
            container = Path(td) / 'containers' / 'sh-7f3a9c21.hc'
            mount = Path(td) / 'mounts' / 'sh-7f3a9c21'

            backend.create_volume(container, size='512M', filesystem='ext4', password='secret')
            backend.mount_volume(container, mount, password='secret')

            self.assertTrue(container.is_file())
            self.assertTrue(mount.is_dir())
            self.assertEqual(backend.mounted(), {container: mount})

            backend.unmount(mount)
            self.assertEqual(backend.mounted(), {})

    def test_fake_veracrypt_backend_refuses_overwrite_and_busy_mount(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            backend = safehouse.FakeVeraCryptBackend()
            container = Path(td) / 'containers' / 'sh-7f3a9c21.hc'
            mount = Path(td) / 'mounts' / 'sh-7f3a9c21'
            backend.create_volume(container, size='512M', filesystem='ext4', password='secret')
            mount.mkdir(parents=True)
            (mount / 'keep.txt').write_text('valuable', encoding='utf-8')

            with self.assertRaises(RuntimeError):
                backend.create_volume(container, size='512M', filesystem='ext4', password='secret')
            with self.assertRaises(RuntimeError):
                backend.mount_volume(container, mount, password='secret')

    def test_veracrypt_errors_redact_secret_from_native_output(self) -> None:
        secret = 'super-secret-passphrase'
        adapter = safehouse.VeraCryptAdapter(
            command='veracrypt',
            runner=lambda call: (_ for _ in ()).throw(RuntimeError(f'native error mentioned {secret}')),
        )

        with self.assertRaises(RuntimeError) as caught:
            adapter.create_volume(Path('/safehouse/containers/sh-7f3a9c21.hc'), '512M', 'ext4', secret)

        self.assertNotIn(secret, str(caught.exception))
        self.assertIn('[REDACTED]', str(caught.exception))

    def test_veracrypt_privilege_error_explains_sudo_cache_without_running_safehouse_as_root(self) -> None:
        def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            del kwargs
            return subprocess.CompletedProcess(
                args=cast(list[str], args[0]),
                returncode=1,
                stdout='',
                stderr='Error: Failed to obtain administrator privileges.\n',
            )

        adapter = safehouse.VeraCryptAdapter(command='veracrypt')

        with mock.patch('safehouse.subprocess.run', fake_run):
            with self.assertRaises(RuntimeError) as caught:
                adapter.create_volume(Path('/safehouse/containers/sh-7f3a9c21.hc'), '512M', 'ext4', 'super-secret-passphrase')

        message = str(caught.exception)
        self.assertIn('Failed to obtain administrator privileges', message)
        self.assertIn('run sudo -v first', message)
        self.assertIn('do not run Safehouse itself with sudo', message)
        self.assertNotIn('super-secret-passphrase', message)

    def test_create_safehouse_orchestrates_container_mount_scaffold_and_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            container_dir = Path(td) / 'containers'
            paths = safehouse.AppPaths.from_home(home)
            config = safehouse.ConfigStore(paths)
            state = safehouse.StateStore(paths)
            backend = safehouse.FakeVeraCryptBackend()
            config.set_category_default('engagement', 'path', str(container_dir))
            config.set_category_default('engagement', 'container-size', '512M')
            config.set_category_default('engagement', 'obsidian-profile', 'minimal')

            created = safehouse.create_safehouse(
                category='engagement',
                name='Client Safe Name',
                config=config,
                state=state,
                backend=backend,
                password='secret-passphrase',
                id_rng=lambda n: b'\x7f:\x9c!',
            )

            self.assertEqual(created.safehouse_id, 'sh-7f3a9c21')
            self.assertEqual(created.container_path, container_dir / 'client-safe-name' / 'sh-7f3a9c21.hc')
            self.assertEqual(created.mount_path, container_dir / 'client-safe-name' / 'mount')
            self.assertTrue(created.container_path.is_file())
            self.assertTrue((created.mount_path / '00_run.md').is_file())
            self.assertTrue((created.mount_path / '00_access.md').is_file())
            self.assertEqual(backend.mounted(), {created.container_path: created.mount_path})

            records = state.records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].safehouse_id, 'sh-7f3a9c21')
            self.assertEqual(records[0].display_name, 'Client Safe Name')
            self.assertEqual(records[0].slug, 'client-safe-name')
            self.assertEqual(records[0].category, 'engagement')
            self.assertEqual(records[0].phase, 'ready')
            self.assertNotIn('secret-passphrase', paths.state_file.read_text(encoding='utf-8'))

    def test_state_store_rejects_retired_kind_field(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            paths.config_dir.mkdir(parents=True)
            paths.state_file.write_text(json.dumps({
                'safehouses': [{
                    'safehouse_id': 'sh-11111111',
                    'display_name': 'Old Dogfood Lab',
                    'slug': 'old-dogfood-lab',
                    'kind': 'lab',
                    'storage': 'plain',
                    'container_path': '',
                    'mount_path': str(Path(td) / 'labs' / 'old-dogfood-lab'),
                    'size': '',
                    'filesystem': '',
                    'phase': 'ready',
                    'created_at': '',
                    'last_opened_at': '',
                }],
            }), encoding='utf-8')
            state = safehouse.StateStore(paths)

            with self.assertRaises(ValueError):
                state.records()

    def test_create_safehouse_records_failed_setup_without_deleting_container(self) -> None:
        class FailingMountBackend(safehouse.FakeVeraCryptBackend):
            def mount_volume(self, container_path: Path, mount_path: Path, password: str) -> str:
                raise RuntimeError('simulated mount failure')

        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            container_dir = Path(td) / 'containers'
            paths = safehouse.AppPaths.from_home(home)
            config = safehouse.ConfigStore(paths)
            state = safehouse.StateStore(paths)
            backend = FailingMountBackend()
            config.set_category_default('engagement', 'path', str(container_dir))
            config.set_category_default('engagement', 'container-size', '512M')
            config.set_category_default('engagement', 'obsidian-profile', 'minimal')

            with self.assertRaises(RuntimeError):
                safehouse.create_safehouse(
                    category='engagement',
                    name='Failure Engagement',
                    config=config,
                    state=state,
                    backend=backend,
                    password='secret-passphrase',
                    id_rng=lambda n: b'\x7f:\x9c!',
                )

            container = container_dir / 'failure-engagement' / 'sh-7f3a9c21.hc'
            self.assertTrue(container.is_file())
            records = state.records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].phase, 'failed_setup')
            self.assertEqual(records[0].container_path, str(container))
            self.assertNotIn('secret-passphrase', paths.state_file.read_text(encoding='utf-8'))

    def test_create_safehouse_lab_defaults_to_plain_safehouse_without_veracrypt(self) -> None:
        class ExplodingBackend:
            def create_volume(self, *args: object, **kwargs: object) -> str:
                raise AssertionError('plain labs must not call VeraCrypt create')

            def mount_volume(self, *args: object, **kwargs: object) -> str:
                raise AssertionError('plain labs must not call VeraCrypt mount')

        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            lab_dir = Path(td) / '40_Labs_&_Engagements'
            paths = safehouse.AppPaths.from_home(home)
            config = safehouse.ConfigStore(paths)
            state = safehouse.StateStore(paths)
            config.set_category_default('lab', 'path', str(lab_dir))

            created = safehouse.create_safehouse(
                category='lab',
                name='Odyssey',
                config=config,
                state=state,
                backend=ExplodingBackend(),
                password='',
                id_rng=lambda n: b'\x7f:\x9c!',
            )

            self.assertEqual(created.slug, 'odyssey')
            self.assertEqual(created.container_path, Path(''))
            self.assertEqual(created.mount_path, lab_dir / 'odyssey')
            self.assertTrue((lab_dir / 'odyssey' / '00_run.md').is_file())
            self.assertTrue((lab_dir / 'odyssey' / '00_access.md').is_file())
            records = state.records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].category, 'lab')
            self.assertEqual(records[0].storage, 'plain')
            self.assertEqual(records[0].container_path, '')
            self.assertEqual(records[0].mount_path, str(lab_dir / 'odyssey'))
            self.assertEqual(records[0].phase, 'ready')

    def test_create_safehouse_lab_uses_builtin_lab_dir_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)

            created = safehouse.create_safehouse(
                category='lab',
                name='Odyssey',
                config=safehouse.ConfigStore(paths),
                state=state,
                backend=safehouse.FakeVeraCryptBackend(),
                password='',
            )

            self.assertEqual(created.mount_path, home / 'safehouse' / 'labs' / 'odyssey')
            self.assertTrue((created.mount_path / '00_run.md').is_file())

    def test_create_safehouse_engagement_defaults_to_encrypted_backend(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            container_dir = Path(td) / 'containers'
            paths = safehouse.AppPaths.from_home(home)
            config = safehouse.ConfigStore(paths)
            state = safehouse.StateStore(paths)
            backend = safehouse.FakeVeraCryptBackend()
            config.set_category_default('engagement', 'path', str(container_dir))
            config.set_category_default('engagement', 'container-size', '512M')
            config.set_category_default('engagement', 'obsidian-profile', 'minimal')

            created = safehouse.create_safehouse(
                category='engagement',
                name='Client Safe Name',
                config=config,
                state=state,
                backend=backend,
                password='secret-passphrase',
                id_rng=lambda n: b'\x7f:\x9c!',
            )

            self.assertTrue(created.container_path.is_file())
            self.assertTrue((created.mount_path / '00_run.md').is_file())
            records = state.records()
            self.assertEqual(records[0].storage, 'encrypted')
            self.assertEqual(records[0].container_path, str(container_dir / 'client-safe-name' / 'sh-7f3a9c21.hc'))

    def test_resize_dry_run_previews_copy_forward_without_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            state = safehouse.StateStore(paths)
            container_dir = Path(td) / 'containers'
            mount_dir = Path(td) / 'mounts'
            container = container_dir / 'sh-11111111.hc'
            mount = mount_dir / 'sh-11111111'
            container.parent.mkdir(parents=True)
            mount.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe Name', slug='client-safe-name', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            exit_code, lines = safehouse.dry_run_resize_safehouse(state, 'Client Safe Name', '1G', id_rng=lambda n: b'\x7f:\x9c!')

            output = '\n'.join(lines)
            self.assertEqual(exit_code, 0)
            self.assertIn('DRY-RUN safehouse resize Client Safe Name --to-size 1G', output)
            self.assertIn(f'Source container: {container}', output)
            self.assertIn(f'New container path: {container_dir / "sh-7f3a9c21.hc"}', output)
            self.assertIn(f'Would preserve old container: {container}', output)
            self.assertIn('Would copy mounted Safehouse data to new container', output)
            self.assertIn('No files changed; no containers created; no mounts opened.', output)
            self.assertFalse((container_dir / 'sh-7f3a9c21.hc').exists())
            self.assertEqual(state.records()[0].safehouse_id, 'sh-11111111')

    def test_remove_dry_run_and_confirmed_delete_only_remove_closed_safehouses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            container = Path(td) / 'engagements' / 'client-safe' / 'sh-11111111.hc'
            mount = container.parent / 'mount'
            superseded = container.parent / 'sh-22222222.hc'
            container.parent.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            superseded.write_text('older fake volume', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            plan = safehouse.plan_remove_safehouse(state, safehouse.FakeVeraCryptBackend(), 'Client Safe')

            self.assertIn(f'Would delete encrypted Safehouse directory tree: {container.parent}', plan)
            self.assertIn('Would remove registry record: sh-11111111', plan)
            self.assertTrue(container.is_file())
            self.assertTrue(superseded.is_file())
            self.assertEqual([item.safehouse_id for item in state.records()], ['sh-11111111'])

            removed = safehouse.remove_safehouse(state, safehouse.FakeVeraCryptBackend(), 'Client Safe')

            self.assertEqual(removed.safehouse_id, 'sh-11111111')
            self.assertFalse(container.exists())
            self.assertFalse(superseded.exists())
            self.assertFalse(container.parent.exists())
            self.assertEqual(state.records(), [])

    def test_remove_refuses_mounted_safehouse_without_deleting_artifact_or_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            state = safehouse.StateStore(paths)
            backend = safehouse.FakeVeraCryptBackend()
            container = Path(td) / 'engagements' / 'client-safe' / 'sh-11111111.hc'
            mount = container.parent / 'mount'
            backend.create_volume(container, size='512M', filesystem='ext4', password='throwaway')
            backend.mount_volume(container, mount, password='throwaway')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='ready',
            ))

            with self.assertRaises(RuntimeError) as caught:
                safehouse.remove_safehouse(state, backend, 'Client Safe')

            self.assertIn('unmount it before removal', str(caught.exception))
            self.assertTrue(container.is_file())
            self.assertEqual([item.safehouse_id for item in state.records()], ['sh-11111111'])

    def test_remove_cli_requires_explicit_yes_after_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            lab = Path(td) / 'labs' / 'odyssey'
            lab.mkdir(parents=True)
            (lab / 'note.md').write_text('remove me\n', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Odyssey', slug='odyssey', category='lab', storage='plain',
                container_path='', mount_path=str(lab), size='', filesystem='', phase='ready',
            ))

            preview = self.run_cli_with_home(home, 'remove', 'Odyssey', '--dry-run')
            refused = self.run_cli_with_home(home, 'remove', 'Odyssey')

            self.assertEqual(preview.returncode, 0, preview.stderr)
            self.assertIn('DRY-RUN safehouse remove Odyssey', preview.stdout)
            self.assertTrue(lab.is_dir())
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('requires --yes after reviewing --dry-run', refused.stderr)
            self.assertEqual([item.safehouse_id for item in state.records()], ['sh-11111111'])

            removed = self.run_cli_with_home(home, 'remove', 'Odyssey', '--yes')

            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertIn('removed sh-11111111 Odyssey', removed.stdout)
            self.assertFalse(lab.exists())
            self.assertEqual(state.records(), [])

    def test_resize_dry_run_refuses_plain_labs_and_missing_containers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            state = safehouse.StateStore(paths)
            missing_container = Path(td) / 'containers' / 'sh-22222222.hc'
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Odyssey', slug='odyssey', category='lab', storage='plain',
                container_path='', mount_path=str(Path(td) / 'labs' / 'odyssey'), size='', filesystem='', phase='ready',
            ))
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-22222222', display_name='Broken Client', slug='broken-client', category='engagement', storage='encrypted',
                container_path=str(missing_container), mount_path=str(Path(td) / 'mounts' / 'sh-22222222'), size='512M', filesystem='ext4', phase='closed',
            ))
            missing_container.parent.mkdir(parents=True)
            missing_container.write_text('fake volume', encoding='utf-8')

            with self.assertRaises(RuntimeError) as lab_error:
                safehouse.dry_run_resize_safehouse(state, 'Odyssey', '1G')
            shrink_exit_code, shrink_lines = safehouse.dry_run_resize_safehouse(
                state, 'Broken Client', '256M', id_rng=lambda n: b'\x7f:\x9c!'
            )
            missing_container.unlink()
            with self.assertRaises(RuntimeError) as missing_error:
                safehouse.dry_run_resize_safehouse(state, 'Broken Client', '1G')

            self.assertIn('plain lab has no VeraCrypt container to resize', str(lab_error.exception))
            self.assertEqual(shrink_exit_code, 0)
            self.assertIn('Target size: 256M', '\n'.join(shrink_lines))
            self.assertIn('missing source container', str(missing_error.exception))

    def test_resize_safehouse_copies_verifies_and_switches_active_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            state = safehouse.StateStore(paths)
            backend = safehouse.FakeVeraCryptBackend()
            root = Path(td) / 'containers' / 'client-safe'
            container = root / 'sh-11111111.hc'
            mount = root / 'mount'
            backend.create_volume(container, size='512M', filesystem='ext4', password='throwaway')
            backend.mount_volume(container, mount, password='throwaway')
            (mount / '02_notes').mkdir()
            (mount / '02_notes' / 'run.md').write_text('keep this evidence\n', encoding='utf-8')
            backend.unmount(mount)
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            result = safehouse.resize_safehouse(
                state, backend, 'Client Safe', '1G', password='throwaway', id_rng=lambda n: b'\x7f:\x9c!'
            )

            active = state.records()[0]
            self.assertEqual(active.safehouse_id, 'sh-11111111')
            self.assertEqual(active.size, '1G')
            self.assertNotEqual(active.container_path, str(container))
            self.assertTrue(Path(active.container_path).is_file())
            self.assertTrue(container.is_file())
            self.assertEqual(backend.mounted(), {Path(active.container_path): mount})
            self.assertEqual((mount / '02_notes' / 'run.md').read_text(encoding='utf-8'), 'keep this evidence\n')
            self.assertEqual(result.file_count, 1)
            self.assertEqual(result.total_bytes, len('keep this evidence\n'.encode('utf-8')))
            backend.unmount(mount)
            removed = safehouse.remove_safehouse(state, backend, 'Client Safe')
            self.assertEqual(removed.safehouse_id, 'sh-11111111')
            self.assertFalse(root.exists())

    def test_resize_safehouse_mounts_source_read_only_before_copying(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            state = safehouse.StateStore(paths)
            backend = safehouse.FakeVeraCryptBackend()
            container = Path(td) / 'containers' / 'sh-11111111.hc'
            mount = Path(td) / 'safehouse' / 'mount'
            backend.create_volume(container, size='512M', filesystem='ext4', password='throwaway')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))
            calls: list[tuple[Path, Path, bool]] = []
            original_mount = backend.mount_volume

            def record_mount(container_path: Path, mount_path: Path, password: str, read_only: bool = False) -> str:
                calls.append((container_path, mount_path, read_only))
                return original_mount(container_path, mount_path, password, read_only)

            backend.mount_volume = record_mount
            safehouse.resize_safehouse(state, backend, 'Client Safe', '1G', password='throwaway', id_rng=lambda n: b'\x7f:\x9c!')

            self.assertTrue(calls[0][2])

    def test_resize_safehouse_rejects_too_small_target_before_creating_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            state = safehouse.StateStore(paths)
            backend = safehouse.FakeVeraCryptBackend()
            container = Path(td) / 'containers' / 'sh-11111111.hc'
            mount = Path(td) / 'safehouse' / 'mount'
            backend.create_volume(container, size='512M', filesystem='ext4', password='throwaway')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            with self.assertRaises(RuntimeError) as caught:
                safehouse.resize_safehouse(state, backend, 'Client Safe', '64M', password='throwaway', id_rng=lambda n: b'\x7f:\x9c!')

            self.assertIn('target size is too small', str(caught.exception))
            self.assertEqual(state.records()[0].container_path, str(container))
            self.assertFalse((container.parent / 'sh-7f3a9c21.hc').exists())
            self.assertEqual(backend.mounted(), {})

    def test_resize_safehouse_refuses_mounted_source_without_switching_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paths = safehouse.AppPaths.from_home(Path(td) / 'home')
            state = safehouse.StateStore(paths)
            backend = safehouse.FakeVeraCryptBackend()
            container = Path(td) / 'containers' / 'sh-11111111.hc'
            mount = Path(td) / 'safehouse' / 'mount'
            backend.create_volume(container, size='512M', filesystem='ext4', password='throwaway')
            backend.mount_volume(container, mount, password='throwaway')

            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='ready',
            ))

            with self.assertRaises(RuntimeError) as caught:
                safehouse.resize_safehouse(state, backend, 'Client Safe', '1G', password='throwaway', id_rng=lambda n: b'\x7f:\x9c!')

            self.assertIn('source Safehouse is mounted', str(caught.exception))
            self.assertEqual(state.records()[0].container_path, str(container))
            self.assertTrue(container.is_file())

    def test_resize_cli_empty_input_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            container = Path(td) / 'containers' / 'sh-11111111.hc'
            mount = Path(td) / 'mounts' / 'sh-11111111'
            container.parent.mkdir(parents=True)
            mount.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe Name', slug='client-safe-name', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            result = self.run_cli_with_home(home, 'resize', 'Client Safe Name', '--to-size', '1G', '--dry-run')
            without_dry_run = self.run_cli_with_home(home, 'resize', 'Client Safe Name', '--to-size', '1G')

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('DRY-RUN safehouse resize Client Safe Name --to-size 1G', result.stdout)
            self.assertIn('Would prompt for VeraCrypt password: yes', result.stdout)
            self.assertIn('No files changed; no containers created; no mounts opened.', result.stdout)
            self.assertNotIn('secret', result.stdout.lower())
            self.assertNotEqual(without_dry_run.returncode, 0)
            self.assertIn('interactive terminal', without_dry_run.stderr)
            self.assertEqual(safehouse.StateStore(paths).records()[0].container_path, str(container))

    def test_resize_cli_runs_copy_forward_and_retains_old_container_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            container = Path(td) / 'containers' / 'sh-11111111.hc'
            mount = Path(td) / 'safehouse' / 'mount'
            container.parent.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            result = self.run_tty_cli_with_home(
                home, 'resize', 'Client Safe', '--to-size', '1G', password_values=['throwaway'], extra_env={'SAFEHOUSE_BACKEND': 'fake'}
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('resized sh-11111111 Client Safe', result.stdout)
            self.assertIn('Old container retained:', result.stdout)
            active = safehouse.StateStore(paths).records()[0]
            self.assertEqual(active.size, '1G')
            self.assertNotEqual(active.container_path, str(container))
            self.assertTrue(container.is_file())

    def test_resize_cli_delete_old_requires_explicit_flag_and_runs_after_switch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            container = Path(td) / 'containers' / 'sh-11111111.hc'
            mount = Path(td) / 'safehouse' / 'mount'
            container.parent.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe', slug='client-safe', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            result = self.run_tty_cli_with_home(
                home, 'resize', 'Client Safe', '--to-size', '1G', '--delete-old', password_values=['throwaway'], extra_env={'SAFEHOUSE_BACKEND': 'fake'}
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Old container deleted:', result.stdout)
            active = safehouse.StateStore(paths).records()[0]
            self.assertTrue(Path(active.container_path).is_file())
            self.assertFalse(container.exists())

    def test_resize_interactive_delete_confirmation_defaults_to_no(self) -> None:
        with mock.patch('safehouse.sys.stdin.isatty', return_value=True), mock.patch('builtins.input', return_value=''):
            self.assertFalse(safehouse.confirm_resize_old_deletion(Path('/tmp/old.hc')))
        with mock.patch('safehouse.sys.stdin.isatty', return_value=True), mock.patch('builtins.input', return_value='yes'):
            self.assertTrue(safehouse.confirm_resize_old_deletion(Path('/tmp/old.hc')))
        with mock.patch('safehouse.sys.stdin.isatty', return_value=False), mock.patch('builtins.input') as prompt:
            self.assertFalse(safehouse.confirm_resize_old_deletion(Path('/tmp/old.hc')))
            prompt.assert_not_called()

    def test_resize_cli_json_reports_scriptable_dry_run_without_secret_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            container = Path(td) / 'containers' / 'sh-11111111.hc'
            mount = Path(td) / 'mounts' / 'sh-11111111'
            container.parent.mkdir(parents=True)
            mount.mkdir(parents=True)
            container.write_text('fake volume', encoding='utf-8')
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Client Safe Name', slug='client-safe-name', category='engagement', storage='encrypted',
                container_path=str(container), mount_path=str(mount), size='512M', filesystem='ext4', phase='closed',
            ))

            result = self.run_cli_with_home(home, 'resize', 'Client Safe Name', '--to-size', '1G', '--dry-run', '--json')

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload['exit_code'], 0)
            self.assertEqual(payload['safehouse_id'], 'sh-11111111')
            self.assertEqual(payload['display_name'], 'Client Safe Name')
            self.assertEqual(payload['current_size'], '512M')
            self.assertEqual(payload['target_size'], '1G')
            self.assertEqual(payload['source_container'], str(container))
            self.assertRegex(payload['target_id'], r'^sh-[0-9a-f]{8}$')
            self.assertIn('create replacement VeraCrypt container', payload['steps'])
            self.assertTrue(payload['will_prompt'])
            self.assertFalse(payload['will_write'])
            self.assertNotIn('secret', result.stdout.lower())
            self.assertNotIn('password', result.stdout.lower())

    def test_resize_cli_json_reports_refusals_as_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            paths = safehouse.AppPaths.from_home(home)
            state = safehouse.StateStore(paths)
            missing_container = Path(td) / 'containers' / 'sh-11111111.hc'
            state.upsert(safehouse.SafehouseRecord(
                safehouse_id='sh-11111111', display_name='Broken Client', slug='broken-client', category='engagement', storage='encrypted',
                container_path=str(missing_container), mount_path=str(Path(td) / 'mounts' / 'sh-11111111'), size='512M', filesystem='ext4', phase='closed',
            ))

            result = self.run_cli_with_home(home, 'resize', 'Broken Client', '--to-size', '1G', '--dry-run', '--json')

            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, '')
            payload = json.loads(result.stdout)
            self.assertEqual(payload['exit_code'], 2)
            self.assertEqual(payload['safehouse_id'], 'sh-11111111')
            self.assertEqual(payload['display_name'], 'Broken Client')
            self.assertIn('missing source container', payload['warning'])
            self.assertIn('inspect state', payload['next'])
            self.assertFalse(payload['will_write'])
            self.assertNotIn('secret', result.stdout.lower())
            self.assertNotIn('password', result.stdout.lower())

if __name__ == '__main__':
    unittest.main()
