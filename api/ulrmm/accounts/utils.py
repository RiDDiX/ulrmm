# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re
import time

import pyotp
from django.conf import settings
from django.core.cache import cache
from rest_framework.exceptions import APIException

from accounts.models import TOTP_UNREADABLE
from ulrmm.constants import CONSOLE_STEPUP_CACHE_PREFIX, TOTP_PENDING_CACHE_PREFIX

TOTP_PENDING_EXPIRE = 600
TOTP_FAIL_LIMIT = 5
TOTP_FAIL_EXPIRE = 600
CONSOLE_STEPUP_EXPIRE = 3600
# a used code stays burnt for the whole window pyotp accepts it in
TOTP_USED_EXPIRE = 120

DELETE_NEEDS_TOTP = "Deleting needs a current code from your authenticator app."
CHANGE_NEEDS_TOTP = (
    "Changing other accounts or roles needs a current code "
    "from your authenticator app."
)

TOTP_UNREADABLE_MSG = (
    "Two-factor key unreadable, an administrator must reset "
    "two-factor authentication."
)

_SIX_DIGITS = re.compile(r"\d{6}")


class TOTPUnreadable(APIException):
    status_code = 400
    default_detail = TOTP_UNREADABLE_MSG
    default_code = "totp_unreadable"


def totp_unreadable(user) -> bool:
    return user.totp_key == TOTP_UNREADABLE


def verify_fresh_totp(user, code, secret: str = "") -> bool:
    """One-use TOTP check shared by login, step-up, self reset and deletes.
    Every well-formed attempt counts before it is checked, so parallel
    guesses cannot slip past the lockout. A key that cannot be decrypted
    raises TOTPUnreadable."""
    secret = secret or user.totp_key
    if secret == TOTP_UNREADABLE:
        raise TOTPUnreadable()
    code = str(code or "").replace(" ", "")
    if not secret or not _SIX_DIGITS.fullmatch(code):
        return False

    fails = f"totp_fail_{user.pk}"
    cache.add(fails, 0, TOTP_FAIL_EXPIRE)
    try:
        attempts = cache.incr(fails)
    except ValueError:
        attempts = 0
    if attempts > TOTP_FAIL_LIMIT:
        return False

    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return False
    if not cache.add(f"totp_used_{user.pk}_{code}", 1, TOTP_USED_EXPIRE):
        return False

    try:
        cache.decr(fails)
    except ValueError:
        pass
    return True


def _stepup_key(user, digest: str = "") -> str:
    key = f"{CONSOLE_STEPUP_CACHE_PREFIX}{user.pk}"
    return f"{key}_{digest}" if digest else key


def grant_console_stepup(user) -> None:
    expires = time.time() + CONSOLE_STEPUP_EXPIRE
    # the per-user entry is what the Mesh sync reads
    cache.set(_stepup_key(user), expires, CONSOLE_STEPUP_EXPIRE)
    digest = getattr(user, "auth_digest", "")
    if digest:
        cache.set(_stepup_key(user, digest), expires, CONSOLE_STEPUP_EXPIRE)


def console_stepup_remaining(user) -> int:
    key = _stepup_key(user, getattr(user, "auth_digest", ""))
    return max(0, int((cache.get(key) or 0) - time.time()))


def drop_console_stepup(user, digests=()) -> None:
    cache.delete_many([_stepup_key(user)] + [_stepup_key(user, d) for d in digests])


def end_other_sessions(user, keep=None) -> None:
    """Ends every dashboard session of the user except ``keep`` and removes
    all of its API keys and the step-up of the ended sessions."""
    from knox.models import AuthToken

    from .models import APIKey

    tokens = AuthToken.objects.filter(user=user)
    if isinstance(keep, AuthToken):
        tokens = tokens.exclude(digest=keep.digest)
    digests = list(tokens.values_list("digest", flat=True))
    tokens.delete()
    APIKey.objects.filter(user=user).delete()

    drop_console_stepup(user, digests)


def _pending_key(user) -> str:
    return f"{TOTP_PENDING_CACHE_PREFIX}{user.pk}"


def set_pending_totp_key(user, key: str) -> None:
    cache.set(_pending_key(user), key, TOTP_PENDING_EXPIRE)


def get_pending_totp_key(user) -> str:
    return cache.get(_pending_key(user)) or ""


def clear_pending_totp_key(user) -> None:
    cache.delete(_pending_key(user))


def commit_pending_totp_key(user, key: str) -> bool:
    # whoever deletes the entry owns the enrolment; a replay finds nothing
    if not cache.delete(_pending_key(user)):
        return False
    user.totp_key = key
    user.save(update_fields=["totp_key"])
    end_other_sessions(user)
    return True


def resolve_pk(model, value):
    """The row a related field of a serializer resolves ``value`` to, or None.
    Guards run on this rather than on a parsed int, since Django also takes
    5.0, " 5" or "5_0" as a pk."""
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        return model.objects.filter(pk=value).first()
    except (TypeError, ValueError):
        return None


def is_root_user(*, request, user) -> bool:
    root = getattr(settings, "ROOT_USER", None)
    if not root or request.user == user:
        return False
    return user.username == root


def is_superuser(user) -> bool:
    return bool(user.role and user.role.is_superuser)


def has_superuser_rights(user) -> bool:
    return bool(user.is_superuser or is_superuser(user))


def audit_role_scope(role, before: dict) -> None:
    """Audit row for a role whose scope (M2M) changed outside its save()."""
    from logs.models import AuditLog
    from ulrmm.middleware import get_debug_info, get_username

    username = get_username()
    after = role.serialize(role)
    if username and after != before:
        AuditLog.audit_object_changed(
            username, "role", before, after, str(role), debug_info=get_debug_info()
        )
