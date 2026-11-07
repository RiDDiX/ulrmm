# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import socket
from contextlib import ExitStack
from unittest import TestCase, mock

from deploy import checksums, tasks

A, B = "ab" * 32, "CD" * 32


def fetch(text):
    r = mock.MagicMock()
    r.__enter__.return_value = r
    r.iter_content.return_value = [text.encode()]
    stack = ExitStack()
    stack.enter_context(
        mock.patch.object(tasks, "_check_host", return_value="93.184.216.34")
    )
    stack.enter_context(mock.patch.object(tasks, "_fetch", return_value=r))
    return stack


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

    def test_sums_url_on_a_private_host_is_refused(self):
        gai = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]
        with (
            mock.patch.object(tasks.socket, "getaddrinfo", return_value=gai),
            mock.patch.object(tasks, "_fetch") as fetch,
        ):
            with self.assertRaisesRegex(ValueError, "private"):
                checksums.expected_sha256(self.url, "https://evil.test/S")
        fetch.assert_not_called()
