# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import functools

import pyotp
import requests
from allauth.account.utils import filter_users_by_email
from allauth.socialaccount import app_settings
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.internal.flows.login import record_authentication
from allauth.socialaccount.models import SocialApp
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import transaction
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError

from .utils import (
    PROVIDER,
    IdPURLError,
    check_idp_url,
    provider_settings,
    public_addresses,
    role_pk,
    sso_enabled,
)


class PinnedHTTPSConnection(HTTPSConnection):
    """Resolves the host once and connects only to those addresses, after they
    passed the address rule, so a second DNS answer cannot point the request
    somewhere internal. TLS still verifies the certificate for the host name."""

    def _new_conn(self):
        if getattr(settings, "SSO_ALLOW_PRIVATE_ISSUER", False):
            return super()._new_conn()

        name = self._dns_host
        try:
            addresses = public_addresses(name, self.port)
        except (IdPURLError, OSError, UnicodeError) as e:
            raise NewConnectionError(
                self, f"Refused to connect to {self.host}: {e}"
            ) from e

        error = None
        for address in addresses:
            # host follows _dns_host, so it is restored before the TLS step
            self._dns_host = address
            try:
                return super()._new_conn()
            except ConnectTimeoutError as e:
                error = e
            finally:
                self._dns_host = name
        raise error


class PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = PinnedHTTPSConnection


class PinnedHTTPAdapter(HTTPAdapter):
    # through a proxy the proxy resolves the name; only the URL check applies
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            **self.poolmanager.pool_classes_by_scheme,
            "https": PinnedHTTPSConnectionPool,
        }


class IdPSession(requests.Session):
    def __init__(self):
        super().__init__()
        self.mount("https://", PinnedHTTPAdapter())

    # send() also sees every redirect, so a hop cannot leave the checked hosts
    def send(self, request, **kwargs):
        try:
            check_idp_url(request.url)
        except IdPURLError as e:
            raise requests.exceptions.InvalidURL(str(e))
        return super().send(request, **kwargs)


class SSOAccountAdapter(DefaultSocialAccountAdapter):
    def list_apps(self, request, provider=None, client_id=None):
        # with SSO off no provider resolves: no login start, no callback, no
        # entry on the login page
        if not sso_enabled():
            return []
        return super().list_apps(request, provider=provider, client_id=client_id)

    def is_open_for_signup(self, request, sociallogin):
        return sso_enabled()

    def pre_social_login(self, request, sociallogin):
        if not sso_enabled():
            raise PermissionDenied("SSO is disabled.")

        if sociallogin.is_existing:
            user = sociallogin.user
            if (
                not user.is_active
                or user.block_dashboard_login
                or user.is_installer_user
                or user.agent_id
            ):
                raise PermissionDenied("This account cannot sign in.")
            return

        # allauth would park a sign-up whose address belongs to another user
        # as a pending signup the dashboard cannot finish. Refuse it instead.
        addresses = {a.email for a in sociallogin.email_addresses if a.email}
        if sociallogin.user.email:
            addresses.add(sociallogin.user.email)
        # filter_users_by_email lowercases the address but matches User.email
        # exactly, and stored addresses keep the case of their local part
        users = get_user_model().objects
        if any(
            users.filter(email__iexact=address).exists()
            or filter_users_by_email(address)
            for address in addresses
        ):
            raise PermissionDenied("The e-mail address belongs to another user.")

    def save_user(self, request, sociallogin, form=None):
        from accounts.models import Role
        from core.tasks import sync_mesh_perms_task

        user = sociallogin.user
        # the provider the identity came from, by its id, not its display name
        app = SocialApp.objects.filter(
            provider=PROVIDER, provider_id=sociallogin.account.provider
        ).first()
        pk = role_pk(provider_settings(app).get("role")) if app else None
        user.role = Role.objects.filter(pk=pk).first() if pk else None
        # never shown or checked; it keeps the MFA enrolment rules from firing.
        # The IdP is trusted to apply MFA.
        user.totp_key = pyotp.random_base32()

        user = super().save_user(request, sociallogin, form=form)
        # allauth records the sign-in only for known identities; the token
        # exchange needs it after the first sign-in too
        record_authentication(request, sociallogin)
        transaction.on_commit(sync_mesh_perms_task.delay)
        return user

    def get_requests_session(self):
        session = IdPSession()
        session.request = functools.partial(
            session.request, timeout=app_settings.REQUESTS_TIMEOUT
        )
        return session
