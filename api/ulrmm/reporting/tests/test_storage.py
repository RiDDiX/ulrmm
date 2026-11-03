# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import os

import pytest
from django.core.exceptions import SuspiciousFileOperation
from django.core.files.base import ContentFile
from django.test import override_settings

from reporting.storage import ReportAssetStorage, get_report_assets_fs

TRAVERSAL = ("../..", "../../etc", "/etc", "temp/../../etc")


@pytest.fixture
def fs(tmp_path):
    root = tmp_path / "assets"
    (root / "temp" / "nested" / "nested").mkdir(parents=True)
    (root / "temp" / "file").write_text("content")
    (root / "temp2" / "nested").mkdir(parents=True)
    (root / "file").write_text("content")
    return ReportAssetStorage(
        location=str(root), base_url="https://api.example.com/reporting/assets/"
    )


def test_isdir(fs):
    assert fs.isdir("temp") and not fs.isdir("file")
    assert not fs.isdir("missing")


def test_rename(fs):
    assert fs.rename("file", "newfilename") == "newfilename"
    assert fs.rename("temp2/nested", "newfoldername") == "temp2/newfoldername"
    assert fs.rename("temp", "newfoldername") == "newfoldername"

    clash = fs.rename("temp2", "newfoldername")
    assert clash.startswith("newfoldername_") and fs.isdir(clash)

    with pytest.raises(FileNotFoundError):
        fs.rename("missing", "other")
    for path in TRAVERSAL:
        with pytest.raises(SuspiciousFileOperation):
            fs.rename(path, "x")
    for name in ("a/b", "..", "", "a\\b"):
        with pytest.raises(SuspiciousFileOperation):
            fs.rename("newfilename", name)


def test_createfolder(fs):
    assert fs.createfolder("temp/newfoldername") == "temp/newfoldername"
    assert fs.createfolder("temp/nested/newfoldername") == "temp/nested/newfoldername"
    clash = fs.createfolder("temp")
    assert clash.startswith("temp_") and fs.isdir(clash)
    with pytest.raises(FileNotFoundError):
        fs.createfolder("missing/child")
    for path in TRAVERSAL + ("",):
        with pytest.raises(SuspiciousFileOperation):
            fs.createfolder(path)


def test_root_is_protected(fs):
    for call in (
        lambda: fs.delete("."),
        lambda: fs.delete_tree(""),
        lambda: fs.delete_tree("temp/.."),
        lambda: fs.rename("", "x"),
    ):
        with pytest.raises(SuspiciousFileOperation):
            call()
    assert os.path.isdir(fs.location)

    fs.delete_tree("temp")
    assert not fs.exists("temp")


def test_symlinks_cannot_leave_the_root(fs, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("secret")
    os.symlink(outside, os.path.join(fs.location, "link"))
    os.symlink(outside / "secret", os.path.join(fs.location, "filelink"))

    assert "link" not in fs.listdir("")[0]
    assert "filelink" not in fs.listdir("")[1]
    for call in (
        lambda: fs.open("filelink"),
        lambda: fs.exists("link/secret"),
        lambda: fs.isdir("link/x"),
        lambda: fs.delete("filelink"),
        lambda: fs.delete_tree("link"),
        lambda: fs.rename("link", "renamed"),
        lambda: fs.save("link/new.png", ContentFile(b"x")),
    ):
        with pytest.raises(SuspiciousFileOperation):
            call()
    assert (outside / "secret").read_text() == "secret"


def test_url_and_settings(tmp_path):
    fs = ReportAssetStorage(
        location=str(tmp_path), base_url="https://api.example.com/reporting/assets/"
    )
    assert fs.url("a b.png") == "https://api.example.com/reporting/assets/a%20b.png"

    with override_settings(
        REPORTING_ASSETS_BASE_PATH=str(tmp_path),
        REPORTING_BASE_URL="https://rmm.example.org/",
    ):
        shared = get_report_assets_fs()
        assert shared.location == str(tmp_path)
        assert shared.url("x.png") == "https://rmm.example.org/reporting/assets/x.png"
