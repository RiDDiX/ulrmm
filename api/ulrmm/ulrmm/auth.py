# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone as djangotime
from knox.auth import TokenAuthentication as KnoxTokenAuthentication
from knox.settings import knox_settings
from rest_framework import HTTP_HEADER_ENCODING
from rest_framework.authentication import BaseAuthentication, TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied

from accounts.models import APIKey, User
from ulrmm.helpers import get_client_ip

# the only dashboard paths a password-only (not yet enrolled) session may reach
MFA_ENROLMENT_PATHS = (
    "/accounts/users/setup_totp/",
    "/logout/",
    "/logoutall/",
)


def needs_mfa_enrolment(user) -> bool:
    return not user.totp_key and not user.is_sso_user


def get_authorization_header(request):
    header = request.META.get("HTTP_X_API_KEY", b"")
    if isinstance(header, str):
        header = header.encode(HTTP_HEADER_ENCODING)
    return header


class APIAuthentication(BaseAuthentication):
    """Authenticates by the ``X-API-KEY`` header against an APIKey's sha256
    hash. Deliberately defines no ``authenticate_header`` so Knox stays the
    source of the ``WWW-Authenticate`` challenge when both are listed.
    """

    def authenticate(self, request):
        header = get_authorization_header(request)
        if not header:
            return None
        try:
            key = header.decode()
        except UnicodeError:
            raise AuthenticationFailed(
                "Invalid token header. Token string should not contain "
                "invalid characters."
            )
        return self.authenticate_credentials(key)

    def authenticate_credentials(self, key):
        key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
        try:
            apikey = APIKey.objects.select_related("user").get(key_hash=key_hash)
        except APIKey.DoesNotExist:
            raise AuthenticationFailed("Invalid token.")

        # installer users must never hold API keys
        if getattr(apikey.user, "is_installer_user", False):
            raise AuthenticationFailed("Invalid token.")
        if not apikey.user.is_active:
            raise AuthenticationFailed("User inactive or deleted.")
        if apikey.expiration and apikey.expiration < djangotime.now():
            raise AuthenticationFailed("The token has expired.")

        return (apikey.user, apikey)


SESSION_EXPIRED = "session expired"


def token_max_ttl() -> timedelta:
    return getattr(settings, "DASHBOARD_TOKEN_MAX_TTL", timedelta(hours=12))


class DashboardTokenAuthentication(KnoxTokenAuthentication):
    """Knox tokens with an absolute lifetime: auto-refresh never carries a
    session past created + DASHBOARD_TOKEN_MAX_TTL."""

    request = None

    def validate_user(self, auth_token):
        if auth_token.user.is_installer_user or auth_token.user.block_dashboard_login:
            raise AuthenticationFailed("Invalid token.")
        if auth_token.created + token_max_ttl() <= djangotime.now():
            from deploy.events import record

            username = auth_token.user.username
            auth_token.delete()
            ip = None
            if self.request is not None:
                ip = get_client_ip(self.request.META)
                # the audit middleware authenticates first; the view then
                # finds no token and has to say why
                self.request._request.session_expired = True
            record(
                "token_expired_max",
                "info",
                ip=ip,
                detail=f"session of {username} reached its maximum lifetime",
            )
            raise AuthenticationFailed(SESSION_EXPIRED)
        user, token = super().validate_user(auth_token)
        # console step-up and websocket checks key off the token digest
        user.auth_digest = auth_token.digest
        return (user, token)

    def renew_token(self, auth_token):
        user = auth_token.user
        # password-only enrolment tokens and installer tokens keep their expiry
        if user.is_installer_user or needs_mfa_enrolment(user):
            return
        current = auth_token.expiry
        cap = auth_token.created + token_max_ttl()
        auth_token.expiry = min(djangotime.now() + knox_settings.TOKEN_TTL, cap)
        # like knox: write only when it moves by more than the refresh interval
        moved = (auth_token.expiry - current).total_seconds()
        if moved > knox_settings.MIN_REFRESH_INTERVAL:
            auth_token.save(update_fields=("expiry",))

    def authenticate(self, request):
        self.request = request
        try:
            result = super().authenticate(request)
        except AuthenticationFailed:
            if getattr(request._request, "session_expired", False):
                raise AuthenticationFailed(SESSION_EXPIRED)
            raise
        if result is not None:
            user = result[0]
            if needs_mfa_enrolment(user) and request.path not in MFA_ENROLMENT_PATHS:
                raise AuthenticationFailed(
                    "Two-factor authentication must be set up first."
                )
        return result


class InstallerTokenAuthentication(KnoxTokenAuthentication):
    """Accepts installer-user and deployment tokens, plus dashboard tokens of
    users that have TOTP set up. Used on the installer/newagent endpoints.
    """

    def renew_token(self, auth_token):
        # never extend an installer or deployment token's lifetime
        return

    def authenticate(self, request):
        result = super().authenticate(request)
        if result is not None:
            user = result[0]
            if not user.is_installer_user and needs_mfa_enrolment(user):
                raise AuthenticationFailed(
                    "Two-factor authentication must be set up first."
                )
        return result


class EnrollmentAuthentication(BaseAuthentication):
    """``Authorization: Enroll <jws>`` from an installer: a signed enrollment
    token of a deployment that still exists unchanged. The request runs as the
    installer user with the Deployment as request.auth.
    """

    keyword = "Enroll"

    def authenticate(self, request):
        from deploy.signing import EnrollmentError, check_deployment, verify

        parts = request.META.get("HTTP_AUTHORIZATION", "").split()
        if not parts or parts[0].lower() != self.keyword.lower():
            return None
        if len(parts) != 2:
            raise AuthenticationFailed("Invalid enrollment header.")
        try:
            deployment = check_deployment(verify(parts[1]))
        except EnrollmentError as e:
            raise AuthenticationFailed(str(e))
        except ImproperlyConfigured:
            raise AuthenticationFailed("Enrollment is not set up on this server.")

        user = User.objects.filter(is_installer_user=True).order_by("pk").first()
        if user is None:
            raise AuthenticationFailed("No installer user exists.")
        if not user.is_active:
            raise AuthenticationFailed("User inactive or deleted.")
        return (user, deployment)

    def authenticate_header(self, request):
        return self.keyword


class TokenExpired(AuthenticationFailed):
    def __init__(self):
        super().__init__("token expired")
        self.detail = {"detail": self.detail, "refresh": True}


class Quarantined(PermissionDenied):
    def __init__(self, new_identity: bool):
        super().__init__("quarantined")
        if new_identity:
            self.detail = {"detail": self.detail, "new_identity": True}


class AgentTokenAuthentication(TokenAuthentication):
    """An agent's access token, looked up by its HMAC digest (DRF tokens
    only for agents that have no credential row yet). A client certificate
    nginx verified must be an active one of that agent; in required mode one
    has to be presented.
    """

    # the certificate view also serves agents without a current certificate
    issuance = False
    # identity registration after "reset identity" runs with the revoked token
    reset_window = False

    def _identity_check(self, agent, revoked: bool) -> None:
        from deploy.models import IdentityState
        from deploy.tokens import identity_of

        ident = identity_of(agent) if agent is not None else None
        if ident is None or ident.state == IdentityState.ACTIVE:
            if revoked:
                raise AuthenticationFailed("token revoked")
            return
        window = (
            ident.state == IdentityState.QUARANTINED
            and ident.release_until is not None
            and ident.release_until > djangotime.now()
        )
        if window and self.reset_window:
            return
        raise Quarantined(window)

    def authenticate_credentials(self, key):
        from deploy.models import AgentCredential, CredentialKind
        from deploy.tokens import lookup

        cred = lookup(key)
        if cred is None:
            user, token = super().authenticate_credentials(key)
            # a non-agent user finds no agent in the views, as before
            if user.agent_id is None:
                return user, token
            if AgentCredential.objects.filter(agent_id=user.agent_id).exists():
                raise AuthenticationFailed("Invalid token.")
            from agents.models import Agent
            from ulrmm.constants import AGENT_DEFER

            agent = Agent.objects.defer(*AGENT_DEFER).filter(pk=user.agent_id).first()
            self._identity_check(agent, revoked=False)
            return user, token
        user = getattr(cred.agent, "user", None)
        if user is None or not user.is_active:
            raise AuthenticationFailed("User inactive or deleted.")
        self._identity_check(cred.agent, revoked=cred.revoked_at is not None)
        if (
            cred.kind == CredentialKind.FAMILY
            and cred.access_expires is not None
            and cred.access_expires <= djangotime.now()
        ):
            raise TokenExpired()
        if cred.kind == CredentialKind.FAMILY and cred.access_used_at is None:
            # the refresh retry hands out this pair only while it is unused
            cred.access_used_at = djangotime.now()
            AgentCredential.objects.filter(
                pk=cred.pk, access_digest=cred.access_digest, access_used_at=None
            ).update(access_used_at=cred.access_used_at)
        return user, cred

    def authenticate(self, request):
        from deploy.pki import client_cert_error

        result = super().authenticate(request)
        if result is not None:
            error = client_cert_error(request, result[0], issuance=self.issuance)
            if error:
                from deploy.events import record
                from deploy.pki import presented

                fingerprint = presented(request)
                record(
                    "cert_refused",
                    "warning",
                    agent=result[0].agent,
                    ip=get_client_ip(request.META),
                    detail=f"{error} ({fingerprint})" if fingerprint else error,
                )
                raise AuthenticationFailed(error)
        return result


class AgentCertAuthentication(AgentTokenAuthentication):
    issuance = True


class AgentIdentityAuthentication(AgentTokenAuthentication):
    reset_window = True
