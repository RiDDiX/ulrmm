# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest import TestCase, mock

from deploy import checksums

A, B = "ab" * 32, "CD" * 32


def fetch(text):
    r = mock.MagicMock()
    r.__enter__.return_value = r
    r.iter_content.return_value = [text.encode()]
    return mock.patch.object(checksums.requests, "get", return_value=r)


class TestChecksums(TestCase):
    url = "https://m.test/dir/os%201.iso?x=1"

    def test_gnu_formats(self):
        text = f"{A}  other.iso\n{B} *os 1.iso\n"
        with fetch(text):
            self.assertEqual(
                checksums.expected_sha256(self.url, "https://m.test/S"), B.lower()
            )

    def test_bsd_format(self):
        with fetch(f"SHA256 (os 1.iso) = {A}\n"):
            self.assertEqual(checksums.expected_sha256(self.url, "https://m.test/S"), A)

    def test_missing_and_scheme(self):
        with fetch(f"{A}  other.iso\n"):
            with self.assertRaisesRegex(ValueError, "no checksum for os 1.iso"):
                checksums.expected_sha256(self.url, "https://m.test/S")
        with self.assertRaises(ValueError):
            checksums.expected_sha256(self.url, "http://m.test/S")
