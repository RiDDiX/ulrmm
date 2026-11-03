# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import json
from unittest import mock

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.test import SimpleTestCase

from . import meshtoken

ZERO = "00" * 80
KEY = "".join(f"{(i * 37 + 11) & 0xFF:02x}" for i in range(80))
NONCE = bytes((i * 7 + 3) & 0xFF for i in range(12))

# recorded from meshctrl 0.1.15 with fixed random bytes and clock:
# (key, time, get_auth_token("ULRMM-ab12"), get_login_token("user//ULRMM-ab12"))
VECTORS = [
    (
        ZERO,
        1700000000.0,
        "AwoRGB8mLTQ7QklQ4siA@B3ZDpXXTf@9QislyRLAyZXvUcDXuGyeI6Hg9Zrlc0QzhGUn0b$e7Bl7DcjteBDy6bO1ofCBkLMAbgQrFQGh0LeGY8dvjoC$kM6cUQ==",
        "AwoRGB8mLTQ7QklQV15lbEnz$IzC@EFPubCR8k4smhQK$FGasq9Yc6qt4lmDHLt@jsW6ees32yhX5FP$yqHnHuowts2T@MrQjKg5Xt6ZTB2A6$7PjD23tfbsr8cebAj2wYsitAX$08YDwzWMfWtUaWY9qSjYqy6fbxn0mOa$Qio=",
    ),
    (
        ZERO,
        1761900000.75,
        "AwoRGB8mLTQ7QklQVI74DUmsIv61iLbqZ1WZrhLAyZXvUcDXuGyeI6Hg9Zrlc0QzhGUn0b$e7Bl7DcjteBDy6bO1ofCBkLMAbgQrFQGh0LeGY8Fuh4C$kM6cUQ==",
        "AwoRGB8mLTQ7QklQV15lbEnz$IzC@EFPubCR8k4smhQK$FGasq9Yc6qt4lmDHLt@jsW6ees32yhX5FP$yqHnHuowts2T@MrQjKg5Xt6ZTB2A6$7PjD23tfbsr8cebAj2JIw6i3RY9hb$x$DDSVFqgGbDyrJFe8XLHcgqhz9QJbo=",
    ),
    (
        KEY,
        1700000000.0,
        "AwoRGB8mLTQ7QklQ9XYV$kiXVtYE6wmKaC3JJZvF3Z3tLim4osclYmgftw$PBTg9bcUW8fTu9awoCTbaMzemaSa7dULLHZ6JEkMRZ@5Hcwm5Jfwo9a$yCbc5AA==",
        "AwoRGB8mLTQ7QklQV15lbFcwNGzpiZt5GZSFfp21pYOiduP2@Mp@sF7WTB3kvDZFSQfjl7mabOoBmlNDfJHEHmKYT8uBHYc@64Znr5lbjeGuB9qBkqnVci53Oaf88RgHq0NHZ9YDGDDtr3lF43V879BuDIdw0slzV0al3wctUJw=",
    ),
    (
        KEY,
        1761900000.75,
        "AwoRGB8mLTQ7QklQexk9$ulx$3ZFFI6g7kZe9JvF3Z3tLim4osclYmgftw$PBTg9bcUW8fTu9awoCTbaMzemaSa7dULLHZ6JEkMRZ@5Hcwm5Jfop$K$yCbc5AA==",
        "AwoRGB8mLTQ7QklQV15lbFcwNGzpiZt5GZSFfp21pYOiduP2@Mp@sF7WTB3kvDZFSQfjl7mabOoBmlNDfJHEHmKYT8uBHYc@64Znr5lbjeGuB9qBkqnVci53Oaf88RgHffHE1DxUgHttV0FEUBUU@Xa7s9eJTkHeBVc478Y8FI8=",
    ),
    (
        KEY.upper(),
        1700000000.0,
        "AwoRGB8mLTQ7QklQ9XYV$kiXVtYE6wmKaC3JJZvF3Z3tLim4osclYmgftw$PBTg9bcUW8fTu9awoCTbaMzemaSa7dULLHZ6JEkMRZ@5Hcwm5Jfwo9a$yCbc5AA==",
        "AwoRGB8mLTQ7QklQV15lbFcwNGzpiZt5GZSFfp21pYOiduP2@Mp@sF7WTB3kvDZFSQfjl7mabOoBmlNDfJHEHmKYT8uBHYc@64Znr5lbjeGuB9qBkqnVci53Oaf88RgHq0NHZ9YDGDDtr3lF43V879BuDIdw0slzV0al3wctUJw=",
    ),
    (
        KEY.upper(),
        1761900000.75,
        "AwoRGB8mLTQ7QklQexk9$ulx$3ZFFI6g7kZe9JvF3Z3tLim4osclYmgftw$PBTg9bcUW8fTu9awoCTbaMzemaSa7dULLHZ6JEkMRZ@5Hcwm5Jfop$K$yCbc5AA==",
        "AwoRGB8mLTQ7QklQV15lbFcwNGzpiZt5GZSFfp21pYOiduP2@Mp@sF7WTB3kvDZFSQfjl7mabOoBmlNDfJHEHmKYT8uBHYc@64Znr5lbjeGuB9qBkqnVci53Oaf88RgHffHE1DxUgHttV0FEUBUU@Xa7s9eJTkHeBVc478Y8FI8=",
    ),
]


def _raw(token):
    return base64.b64decode(token.replace("@", "+").replace("$", "/"))


def gcm_claims(token, key):
    raw = _raw(token)
    aes = AESGCM(bytes.fromhex(key)[:32])
    return json.loads(aes.decrypt(raw[:12], raw[28:] + raw[12:28], None))


def cbc_claims(token, key):
    # the CBC form MeshCentral also reads: key bytes 48-80, 16 byte IV,
    # 48 bytes before the JSON
    raw = _raw(token)
    aes = Cipher(algorithms.AES(bytes.fromhex(key)[48:80]), modes.CBC(raw[:16]))
    dec = aes.decryptor()
    unpad = padding.PKCS7(128).unpadder()
    plain = unpad.update(dec.update(raw[16:]) + dec.finalize()) + unpad.finalize()
    return json.loads(plain[48:])


class MeshTokenTest(SimpleTestCase):
    def tokens(self, key, t):
        with (
            mock.patch.object(meshtoken, "urandom", return_value=NONCE),
            mock.patch.object(meshtoken, "time", return_value=t),
        ):
            return (
                meshtoken.get_auth_token("ULRMM-ab12", key),
                meshtoken.get_login_token(key, "user//ULRMM-ab12"),
            )

    def test_auth_token_matches_recorded(self):
        for key, t, auth, _ in VECTORS:
            with self.subTest(key=key[:4], t=t):
                self.assertEqual(self.tokens(key, t)[0], auth)

    def test_login_token_carries_the_recorded_claims(self):
        # same claims; sealed with GCM like MeshCentral's own login tokens
        for key, t, _, login in VECTORS:
            with self.subTest(key=key[:4], t=t):
                mine = gcm_claims(self.tokens(key, t)[1], key)
                self.assertEqual(mine, cbc_claims(login, key))
                self.assertEqual(
                    mine, {"u": "user//ulrmm-ab12", "a": 3, "time": int(t)}
                )

    def test_login_token_with_unusable_key(self):
        for key in ("bench-not-hex", None, ""):
            with self.subTest(key=key):
                self.assertEqual(meshtoken.get_login_token(key, "user//a"), "err")

    def test_new_nonce_per_token(self):
        self.assertNotEqual(
            meshtoken.get_login_token(KEY, "user//a"),
            meshtoken.get_login_token(KEY, "user//a"),
        )
