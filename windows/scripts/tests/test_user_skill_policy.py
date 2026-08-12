from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "user_skill_policy.py"
SPEC = importlib.util.spec_from_file_location("user_skill_policy", SCRIPT)
assert SPEC and SPEC.loader
policy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = policy
SPEC.loader.exec_module(policy)


class UserSkillPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "S-1-5-21-1-2-3-1001"
        self.data = self.root / "data"
        self.builtins = self.data / "builtin-skills"
        self.skills = self.data / "skills"
        self.workspace = self.root / "workspace"
        for path in (self.builtins / "auto-inject", self.skills, self.workspace):
            path.mkdir(parents=True, exist_ok=True)

        self.reference = Path(self.temp.name) / "reference"
        (self.reference / "auto-inject").mkdir(parents=True)
        for name in sorted(policy.KEEP_BUILTINS | {"mermaid", "cron", "officecli", "skill-creator"}):
            parent = self.reference / "auto-inject" if name in {"cron", "officecli", "skill-creator"} else self.reference
            self.write_skill(parent / name, name)
            target_parent = self.builtins / "auto-inject" if parent.name == "auto-inject" else self.builtins
            self.write_skill(target_parent / name, name)

        self.plugin = Path(__file__).resolve().parents[2] / "plugins" / "llm-wiki"
        self.db = self.data / "aionui-backend.db"
        self.create_database()

    @staticmethod
    def write_skill(path: Path, name: str) -> None:
        path.mkdir(parents=True)
        (path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Managed test Skill {name}.\n---\n\n# {name}\n",
            encoding="utf-8",
        )

    def create_database(self) -> None:
        con = sqlite3.connect(self.db)
        con.executescript(
            """
            CREATE TABLE skills (
              id TEXT PRIMARY KEY, name TEXT UNIQUE, description TEXT, path TEXT,
              source TEXT, enabled INTEGER, deleted_at INTEGER, created_at INTEGER, updated_at INTEGER
            );
            CREATE TABLE assistant_definitions (
              id TEXT PRIMARY KEY, default_skill_ids TEXT, default_disabled_builtin_skill_ids TEXT
            );
            CREATE TABLE assistant_preferences (
              assistant_definition_id TEXT PRIMARY KEY, last_skill_ids TEXT,
              last_disabled_builtin_skill_ids TEXT
            );
            CREATE TABLE assistants (
              id TEXT PRIMARY KEY, enabled_skills TEXT, disabled_builtin_skills TEXT
            );
            """
        )
        disk = policy.scan_builtin_skills(self.builtins)
        for index, (name, path) in enumerate(sorted(disk.items())):
            con.execute(
                "INSERT INTO skills VALUES(?,?,?,?, 'builtin',1,NULL,1,1)",
                (f"skill-{index}", name, f"Description {name}", str(path)),
            )
        custom = self.skills / "keep-custom"
        self.write_skill(custom, "keep-custom")
        con.execute(
            "INSERT INTO skills VALUES('custom','keep-custom','Custom',?,'user',1,NULL,1,1)",
            (str(custom),),
        )
        archived = json.dumps(["mermaid", "pdf"])
        con.execute("INSERT INTO assistant_definitions VALUES('a',?,?)", (archived, archived))
        con.execute("INSERT INTO assistant_preferences VALUES('a',?,?)", (archived, archived))
        con.execute("INSERT INTO assistants VALUES('a',?,?)", (archived, archived))
        con.commit()
        con.close()

    def test_apply_archives_non_allowlisted_and_installs_wiki(self) -> None:
        skill_links = self.workspace / "sample" / ".codex" / "skills"
        skill_links.mkdir(parents=True)
        if os.name == "nt":
            os.symlink(self.builtins / "auto-inject" / "cron", skill_links / "cron", target_is_directory=True)
        plan = policy.plan_policy(self.root, self.plugin, self.reference)
        self.assertEqual(plan["status"], "READY")
        if os.name == "nt":
            self.assertEqual(plan["workspace_link_removal_count"], 1)
        result = policy.apply_policy(self.root, self.plugin, self.reference)
        self.assertTrue(result["changed"])
        self.assertEqual(result["managed_available_count"], 19)
        self.assertTrue((self.skills / "keep-custom" / "SKILL.md").is_file())
        self.assertFalse((self.builtins / "mermaid").exists())
        self.assertFalse((self.builtins / "auto-inject" / "cron").exists())
        for name in policy.KEEP_BUILTINS:
            self.assertIn(name, policy.scan_builtin_skills(self.builtins))
        for name in policy.WIKI_SKILLS:
            target = self.skills / name
            self.assertTrue((target / "scripts" / "wiki_tool.py").is_file())
            self.assertTrue((target / "assets" / "workspace" / "index.md").is_file())
            self.assertTrue((target / "assets" / "workspace" / "log.md").is_file())
            self.assertTrue((target / "assets" / "workspace" / "contract.md").is_file())
            self.assertNotIn("<PLUGIN_ROOT>", (target / "SKILL.md").read_text(encoding="utf-8"))
        if os.name == "nt":
            self.assertFalse(os.path.lexists(skill_links / "cron"))

        project = self.root / "workspace" / "wiki-smoke"
        project.mkdir()
        completed = subprocess.run(
            [
                sys.executable,
                str(self.skills / "wiki-setup" / "scripts" / "wiki_tool.py"),
                "init",
                "--root",
                str(project),
                "--apply",
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue((project / "wiki-llm" / "index.md").is_file())
        self.assertTrue((project / "wiki-llm" / "log.md").is_file())
        self.assertTrue((project / "wiki-llm" / "contract.md").is_file())

        con = sqlite3.connect(self.db)
        active_builtins = {row[0] for row in con.execute("SELECT name FROM skills WHERE source='builtin' AND enabled=1")}
        active_wiki = {
            row[0]
            for row in con.execute(
                "SELECT name FROM skills WHERE source='user' AND enabled=1 AND name LIKE 'wiki-%'"
            )
        }
        self.assertEqual(active_builtins, set(policy.KEEP_BUILTINS))
        self.assertEqual(active_wiki, set(policy.WIKI_SKILLS))
        self.assertEqual(con.execute("SELECT default_skill_ids FROM assistant_definitions").fetchone()[0], '["pdf"]')
        con.close()

        second = policy.apply_policy(self.root, self.plugin, self.reference)
        self.assertFalse(second["changed"])

    def test_refuses_to_overwrite_unmanaged_skill(self) -> None:
        self.write_skill(self.skills / "wiki-setup", "wiki-setup")
        with self.assertRaises(policy.PolicyError):
            policy.apply_policy(self.root, self.plugin, self.reference)

    def test_every_new_user_entrypoint_reuses_the_existing_skill_policy(self) -> None:
        scripts = SCRIPT.parent
        cli_installer = (scripts / "Install-User.ps1").read_text(encoding="utf-8")
        portal_provisioner = (scripts.parent / "internal" / "admin" / "provision.go").read_text(encoding="utf-8")
        install = (scripts / "Install.ps1").read_text(encoding="utf-8")
        upgrade = (scripts / "Upgrade.ps1").read_text(encoding="utf-8")

        self.assertIn("Apply-UserSkillPolicy.ps1", cli_installer)
        self.assertIn("applying_skill_policy", portal_provisioner)
        self.assertIn("Apply-UserSkillPolicy.ps1", portal_provisioner)
        self.assertIn("Publish-UserSkillPolicyBundle.ps1", install)
        self.assertIn("Publish-UserSkillPolicyBundle.ps1", upgrade)
        self.assertNotIn("Install-ManagedWikiSkills.ps1", cli_installer + portal_provisioner + install + upgrade)

    def test_policy_publisher_creates_a_minimal_hash_verified_bundle(self) -> None:
        destination = Path(self.temp.name) / "admin-scripts"
        destination.mkdir()
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(SCRIPT.parent / "Publish-UserSkillPolicyBundle.ps1"),
                "-DestinationDirectory",
                str(destination),
                "-PluginRoot",
                str(self.plugin),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        bundle = destination / "skill-policy"
        self.assertFalse((bundle / "llm-wiki" / "tests").exists())
        manifest = json.loads((bundle / "skill-policy-manifest.json").read_text(encoding="utf-8"))
        for relative, expected in manifest["files"].items():
            content = (bundle / Path(relative)).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), expected["sha256"])
            self.assertEqual(len(content), expected["size"])
        self.assertIn("Apply-UserSkillPolicy.ps1", manifest["files"])
        self.assertIn("llm-wiki/skills/wiki-dream/SKILL.md", manifest["files"])


if __name__ == "__main__":
    unittest.main()
