# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import os
import posixpath
import shutil
from typing import List, Tuple

from django.core.exceptions import SuspiciousFileOperation
from django.core.files.storage import FileSystemStorage
from django.utils._os import safe_join

from . import conf

OUTSIDE_ROOT = "Path is outside the asset folder"


class ReportAssetStorage(FileSystemStorage):
    """File storage for report assets.

    Every relative path resolves inside the asset root, checked lexically and
    again on the real path, so a symlink cannot lead out of it. Location and
    base URL follow the settings unless given explicitly.
    """

    @property
    def base_location(self) -> str:
        return self._location or conf.assets_base_path()

    @property
    def location(self) -> str:
        return os.path.abspath(self.base_location)

    @property
    def base_url(self) -> str:
        url = self._base_url or conf.assets_base_url()
        return url if url.endswith("/") else f"{url}/"

    def path(self, name: str) -> str:
        name = str(name)
        if "\x00" in name or os.path.isabs(name) or name.startswith("\\"):
            raise SuspiciousFileOperation(OUTSIDE_ROOT)
        try:
            full = safe_join(self.location, name)
        except (SuspiciousFileOperation, ValueError):
            raise SuspiciousFileOperation(OUTSIDE_ROOT)

        root = os.path.realpath(self.location)
        real = os.path.realpath(full)
        if real != root and not real.startswith(root + os.sep):
            raise SuspiciousFileOperation(OUTSIDE_ROOT)
        return full

    def relative(self, full: str) -> str:
        rel = os.path.relpath(full, self.location)
        return "" if rel == "." else rel.replace(os.sep, "/")

    def _item(self, path: str) -> str:
        full = self.path(path)
        if full == self.location:
            raise SuspiciousFileOperation("The asset folder itself cannot be changed")
        return full

    def isdir(self, path: str) -> bool:
        return os.path.isdir(self.path(path))

    def listdir(self, path: str) -> Tuple[List[str], List[str]]:
        directories, files = [], []
        with os.scandir(self.path(path)) as entries:
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    directories.append(entry.name)
                else:
                    files.append(entry.name)
        return directories, files

    def rename(self, path: str, new_name: str) -> str:
        if (
            not isinstance(new_name, str)
            or new_name in ("", ".", "..")
            or "/" in new_name
            or "\\" in new_name
            or "\x00" in new_name
        ):
            raise SuspiciousFileOperation("The new name must be a single name")

        full = self._item(path)
        if not os.path.exists(full):
            raise FileNotFoundError("No such file or folder")

        parent = self.relative(os.path.dirname(full))
        target = self.get_available_name(posixpath.join(parent, new_name))
        os.rename(full, self.path(target))
        return target

    def createfolder(self, path: str) -> str:
        full = self._item(path)
        name = self.get_available_name(self.relative(full))
        os.mkdir(self.path(name))
        return name

    def delete(self, name: str) -> None:
        self._item(name)
        super().delete(name)

    def delete_tree(self, path: str) -> None:
        full = self._item(path)
        if os.path.isdir(full):
            shutil.rmtree(full)
        elif os.path.exists(full):
            os.remove(full)


report_assets_fs = ReportAssetStorage()


def get_report_assets_fs() -> ReportAssetStorage:
    return report_assets_fs
