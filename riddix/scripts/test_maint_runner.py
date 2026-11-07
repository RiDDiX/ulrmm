# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""riddix/scripts/maint_runner.sh with stand-ins for update.sh and backup.sh,
and the order of the steps in update.sh."""

import fcntl
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNNER = REPO / "riddix" / "scripts" / "maint_runner.sh"
UPDATE = REPO / "update.sh"
BACKUP = REPO / "backup.sh"


class TestMaintRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.maint, rmm = root / "maint", root / "rmm"
        self.maint.mkdir()
        rmm.mkdir()
        (rmm / "update.sh").write_text('umask\necho "args $*"\n')
        # the real backup.sh up to its own umask
        text = BACKUP.read_text()
        head = text[: text.index("\numask 077\n") + len("\numask 077\n")]
        (rmm / "backup.sh").write_text(head + "umask\nexit 3\n")
        (rmm / "backup.sh").chmod(0o755)
        self.runner = root / "maint_runner.sh"
        self.runner.write_text(RUNNER.read_text().replace("/rmm/", f"{rmm}/"))
        self.env = dict(os.environ, MAINT_DIR=str(self.maint), HOME=str(root))

    def start(self, action):
        (self.maint / "request").write_text(action)
        p = subprocess.Popen(["bash", str(self.runner)], env=self.env)
        self.addCleanup(p.kill)
        return p

    def state(self, action):
        return json.loads((self.maint / f"{action}.state.json").read_text())

    def test_update_runs_under_022_and_the_request_is_gone(self):
        self.assertEqual(self.start("update").wait(timeout=30), 0)
        self.assertFalse((self.maint / "request").exists())
        self.assertEqual((self.maint / "update.log").read_text(), "0022\nargs --yes\n")
        st = self.state("update")
        self.assertEqual(
            (st["action"], st["state"], st["exit_code"]), ("update", "done", 0)
        )
        self.assertLessEqual(st["started"], st["finished"])

    def test_backup_keeps_its_own_umask_077(self):
        self.start("backup").wait(timeout=30)
        self.assertEqual((self.maint / "backup.log").read_text(), "0077\n")
        st = self.state("backup")
        self.assertEqual((st["state"], st["exit_code"]), ("failed", 3))
        self.assertFalse((self.maint / ".backup.state.json").exists())

    def test_a_held_lock_makes_the_runner_wait(self):
        with open(self.maint / "lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            p = self.start("update")
            with self.assertRaises(subprocess.TimeoutExpired):
                p.wait(timeout=1)
            self.assertTrue((self.maint / "request").exists())
            self.assertFalse((self.maint / "update.state.json").exists())
            fcntl.flock(lock, fcntl.LOCK_UN)
            self.assertEqual(p.wait(timeout=30), 0)
        self.assertFalse((self.maint / "request").exists())
        self.assertEqual(self.state("update")["state"], "done")


class TestUpdateOrder(unittest.TestCase):
    def test_everything_that_can_fail_runs_before_the_stop(self):
        text = UPDATE.read_text()
        main = text[text.index("\nmain() {") :]
        stop = main.index('    sudo systemctl stop "$s"\n')
        for step in (
            "    install_python\n",
            'install_nats_server "$NATS_SERVER_VER"',
            'setup_node || die "could not install NodeJS."',
            'mesh_reinstall "$LATEST_MESH_VER"',
            "if ! sudo nginx -t; then",
        ):
            self.assertLess(main.index(step), stop, step)
        self.assertLess(stop, main.index("TREE_REPLACED=true"))
        self.assertNotIn("apt remove -y nodejs", text)

    def test_on_exit_starts_a_meshcentral_the_update_stopped(self):
        text = UPDATE.read_text()
        body = text[: text.rindex('main "$@"; exit')]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, MAINT_DIR=os.path.join(tmp, "none"))
            for flag, started in (("true", True), ("false", False)):
                script = (
                    body
                    + 'sudo() { echo "sudo $*"; }\n'
                    + f"MESH_STOPPED={flag}\ntrap on_exit EXIT\nexit 1\n"
                )
                r = subprocess.run(
                    ["bash", "-c", script],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertEqual(
                    "sudo systemctl start meshcentral" in r.stdout, started, r.stdout
                )


if __name__ == "__main__":
    unittest.main()
