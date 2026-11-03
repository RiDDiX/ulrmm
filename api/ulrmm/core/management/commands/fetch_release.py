# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import shutil
import sys
from pathlib import Path

from django.core.management.base import BaseCommand

from core import releases


class Command(BaseCommand):
    help = (
        "Download the signed release into --dest/<version> and verify it. "
        "Last stdout line is the verified directory. Exit 2: verification "
        "failed, 3: no source answered."
    )

    def create_parser(self, prog_name, subcommand, **kwargs):
        # BaseCommand owns --version; here it is the release to fetch
        kwargs["conflict_handler"] = "resolve"
        return super().create_parser(prog_name, subcommand, **kwargs)

    def add_arguments(self, parser):
        parser.add_argument("--dest", required=True)
        parser.add_argument("--version")
        parser.add_argument("--progress", help="update.progress.json to write")

    def handle(self, *args, **opts):
        dest = Path(opts["dest"])
        progress = opts["progress"]

        def log(line):
            self.stderr.write(line)

        try:
            source, release = releases.discover(opts["version"], log=log)
        except releases.ReleaseError as e:
            if progress:
                releases.write_progress(
                    progress, phase="failed", version=opts["version"], message=str(e)
                )
            self.stderr.write(str(e))
            sys.exit(3)
        version = release["version"]
        cb = releases.progress_writer(progress, source, version) if progress else None
        try:
            path = releases.download_and_verify(release, dest, cb)
        except releases.ReleaseError as e:
            if progress:
                releases.write_progress(
                    progress,
                    phase="failed",
                    source=source,
                    version=version,
                    message=str(e),
                )
            self.stderr.write(str(e))
            sys.exit(2)
        for old in dest.iterdir():
            if old.is_dir() and not old.is_symlink() and old != path:
                shutil.rmtree(old, ignore_errors=True)
        link = dest / "current"
        tmp = dest / ".current"
        tmp.unlink(missing_ok=True)
        tmp.symlink_to(path.name)
        tmp.replace(link)
        if cb:
            cb("verify", release_total(release), release_total(release), "verified")
        self.stdout.write(str(path))


def release_total(release) -> int:
    return sum(a["size"] for a in release["manifest"]["assets"])
