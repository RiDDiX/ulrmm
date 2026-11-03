# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re
import time
from collections import Counter
from urllib.parse import parse_qs, urlsplit

from allauth.account.internal.flows.login import AUTHENTICATION_METHODS_SESSION_KEY
from allauth.socialaccount.internal import statekit
from allauth.socialaccount.internal.statekit import STATES_SESSION_KEY
from allauth.socialaccount.models import SocialAccount, SocialApp
from allauth.socialaccount.providers import registry
from allauth.socialaccount.providers.base.constants import AuthProcess
from allauth.socialaccount.providers.openid_connect import views as oidc_views
from allauth.utils import get_request_param
from django.contrib.auth import logout
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.generic import View
from knox.views import LoginView as KnoxLoginView
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView

from accounts.models import Role
from accounts.permissions import AccountsPerms
from accounts.utils import has_superuser_rights
from core.models import CoreSettings
from core.utils import get_core_settings
from logs.models import AuditLog
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.helpers import get_client_ip, notify_error

from .serializers import (
    DisconnectAccountSerializer,
    SSOProviderInputSerializer,
    SSOProviderSerializer,
    SSOSettingsSerializer,
)
from .utils import (
    EXCHANGE_MAX_AGE,
    PROVIDER,
    derive_provider_id,
    issuer_problem,
    login_callback_url,
    login_error_redirect,
    provider_icon,
    provider_settings,
    role_pk,
    sso_enabled,
)

NO_PENDING_LOGIN = "No pending login session found"

# key in the allauth login state that names the provider the login started at
STATE_PROVIDER_KEY = "sso_provider_id"


def check_provider_rights(user, provider_id: str, role_ids) -> None:
    # whoever controls a provider decides who signs in, with which role and as
    # which linked user. Non-superusers may not control one that superusers
    # sign in with, or one that grants a superuser role, before or after a change.
    if has_superuser_rights(user):
        return

    if (
        SocialAccount.objects.filter(provider=provider_id)
        .filter(Q(user__is_superuser=True) | Q(user__role__is_superuser=True))
        .exists()
    ):
        raise PermissionDenied(
            "Only superusers can manage a provider that superusers sign in with."
        )

    pks = [pk for pk in map(role_pk, role_ids) if pk]
    if Role.objects.filter(pk__in=pks, is_superuser=True).exists():
        raise PermissionDenied(
            "Only superusers can manage a provider with a superuser role."
        )


def _audit_value(app) -> dict:
    conf = provider_settings(app)
    return {
        "name": app.name,
        "provider_id": app.provider_id,
        "client_id": app.client_id,
        "secret_set": bool(app.secret),
        "server_url": conf.get("server_url"),
        "role": conf.get("role"),
    }


def _audit_provider(request, action, verb, app, before=None, after=None) -> None:
    username = request.user.username
    AuditLog.objects.create(
        username=username,
        object_type=AuditObjType.CORE,
        action=action,
        message=f"{username} {verb} SSO provider {app.name}",
        before_value=before,
        after_value=after,
        debug_info={"ip": get_client_ip(request.META)},
    )


def _audit_failed_sso(username, reason, debug_info) -> None:
    AuditLog.objects.create(
        username=username,
        object_type=AuditObjType.USER,
        action=AuditActionType.FAILED_LOGIN,
        message=f"{username} failed to login through SSO: {reason}",
        debug_info=debug_info,
    )


def _single_app(provider_id):
    # a provider_id shared by two rows is ambiguous and never resolves
    apps = list(
        SocialApp.objects.filter(provider=PROVIDER, provider_id=provider_id)[:2]
    )
    return apps[0] if provider_id and len(apps) == 1 else None


class GetAddSSOProviders(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    def get(self, request):
        return Response(SSOProviderSerializer(SocialApp.objects.all(), many=True).data)

    def post(self, request):
        serializer = SSOProviderInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        provider_id = derive_provider_id(data["name"])
        if not re.search(r"[a-z0-9]", provider_id):
            return notify_error("The name needs at least one letter or digit.")

        check_provider_rights(request.user, provider_id, [data.get("role")])

        if (
            registry.get_class(provider_id)
            or SocialApp.objects.filter(provider_id__iexact=provider_id).exists()
        ):
            return notify_error("A provider with this name already exists.")

        app = SocialApp.objects.create(
            provider=PROVIDER,
            provider_id=provider_id,
            name=data["name"],
            client_id=data["client_id"],
            secret="" if data.get("secret_clear") else data.get("secret", ""),
            settings={"server_url": data["server_url"], "role": data.get("role")},
        )
        _audit_provider(
            request, AuditActionType.ADD, "added", app, after=_audit_value(app)
        )
        return Response("ok")


class GetUpdateDeleteSSOProvider(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    def put(self, request, pk):
        app = get_object_or_404(SocialApp, pk=pk)
        if not isinstance(request.data, dict):
            return notify_error("The request body must be an object.")

        # name and provider_id are fixed once created
        body = {
            k: v
            for k, v in request.data.items()
            if k not in ("name", "provider", "provider_id")
        }
        serializer = SSOProviderInputSerializer(data=body, partial=True)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        stored = provider_settings(app)
        role = data["role"] if "role" in data else stored.get("role")
        check_provider_rights(request.user, app.provider_id, [stored.get("role"), role])

        before = _audit_value(app)
        if "client_id" in data:
            app.client_id = data["client_id"]
        # clearing wins over a secret sent in the same body, an empty secret
        # keeps the stored one
        if data.get("secret_clear"):
            app.secret = ""
        elif data.get("secret"):
            app.secret = data["secret"]
        app.settings = {
            "server_url": data.get("server_url", stored.get("server_url")),
            "role": role,
        }
        app.save()

        _audit_provider(
            request,
            AuditActionType.MODIFY,
            "modified",
            app,
            before=before,
            after=_audit_value(app),
        )
        return Response("ok")

    def delete(self, request, pk):
        app = get_object_or_404(SocialApp, pk=pk)
        check_provider_rights(
            request.user, app.provider_id, [provider_settings(app).get("role")]
        )

        # linked identities stay; re-creating the provider under the same name
        # brings them back
        before = _audit_value(app)
        app.delete()
        _audit_provider(request, AuditActionType.DELETE, "deleted", app, before=before)
        return Response("ok")


class GetEditSSOSettings(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    def get(self, request):
        core = get_core_settings()
        return Response(
            {
                "block_local_user_logon": core.block_local_user_logon,
                "sso_enabled": core.sso_enabled,
            }
        )

    def post(self, request):
        if not has_superuser_rights(request.user):
            raise PermissionDenied("Only superusers can change the SSO settings.")

        serializer = SSOSettingsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # the model save keeps local logon open while SSO is off
        core = CoreSettings.objects.first()
        core.sso_enabled = serializer.validated_data["sso_enabled"]
        core.block_local_user_logon = serializer.validated_data[
            "block_local_user_logon"
        ]
        core.save(update_fields=["sso_enabled", "block_local_user_logon"])
        return Response("ok")


class DisconnectSocialAccount(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    def delete(self, request):
        serializer = DisconnectAccountSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        account = get_object_or_404(
            SocialAccount.objects.select_related("user", "user__role"),
            provider=serializer.validated_data["provider"],
            uid=serializer.validated_data["account"],
        )
        user = account.user
        if has_superuser_rights(user) and not has_superuser_rights(request.user):
            raise PermissionDenied(
                "Only superusers can disconnect a superuser's sign-in."
            )

        account.delete()

        username = request.user.username
        AuditLog.objects.create(
            username=username,
            object_type=AuditObjType.USER,
            action=AuditActionType.DELETE,
            message=f"{username} disconnected the {account.provider} sign-in of {user.username}",
            before_value={
                "user": user.username,
                "provider": account.provider,
                "uid": account.uid,
            },
            debug_info={"ip": get_client_ip(request.META)},
        )
        return Response("ok")


class SSOTokenMinThrottle(SimpleRateThrottle):
    # login rates, keyed by client address even though the session user is
    # authenticated
    scope = "login_min"
    cache_format = "throttle_sso_token_%(scope)s_%(ident)s"

    def get_cache_key(self, request, view):
        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }


class SSOTokenDayThrottle(SSOTokenMinThrottle):
    scope = "login_day"


def _display_name(user):
    if user.first_name and user.last_name:
        return f"{user.first_name} {user.last_name}"
    return user.first_name or user.email or None


class SSOTokenExchange(KnoxLoginView):
    """Trades the session left by the IdP callback for a dashboard token.

    Session auth (with CSRF) only. The session is flushed on every outcome, so
    it can be exchanged once.
    """

    authentication_classes = (SessionAuthentication,)
    permission_classes = (IsAuthenticated,)
    throttle_classes = [SSOTokenMinThrottle, SSOTokenDayThrottle]

    def _pending_sign_in(self, request):
        """The latest IdP sign-in recorded in this session, or (None, reason)."""
        user = request.user
        if not sso_enabled():
            return None, "SSO is disabled"
        if user.block_dashboard_login or user.is_installer_user or user.agent_id:
            return None, "dashboard login is blocked"

        methods = request.session.get(AUTHENTICATION_METHODS_SESSION_KEY) or []
        records = [
            m
            for m in methods
            if isinstance(m, dict) and m.get("method") == "socialaccount"
        ]
        if not records:
            return None, "no sign-in recorded"

        record = dict(records[-1])
        try:
            age = time.time() - float(record.get("at"))
        except (TypeError, ValueError):
            return None, "no sign-in recorded"
        if not -60 < age <= EXCHANGE_MAX_AGE:
            return None, "the recorded sign-in has expired"

        provider = record.get("provider")
        if not (
            _single_app(provider)
            and SocialAccount.objects.filter(
                user=user, provider=provider, uid=record.get("uid")
            ).exists()
        ):
            return None, "the identity is no longer linked"

        return record, ""

    def post(self, request, format=None):
        user = request.user
        client_ip = get_client_ip(request.META)

        record, reason = self._pending_sign_in(request)
        if not record:
            _audit_failed_sso(user.username, reason, {"ip": client_ip})
            logout(request)
            return Response(NO_PENDING_LOGIN, status=403)

        response = super().post(request, format=None)

        if client_ip:
            user.last_login_ip = client_ip
            user.save(update_fields=["last_login_ip"])
            record["ip"] = client_ip

        AuditLog.audit_user_login_successful_sso(
            user.username, record["provider"], debug_info=record
        )
        logout(request)

        response.data["username"] = user.username
        response.data["provider"] = record["provider"]
        response.data["name"] = _display_name(user)
        return response


# allauth headless browser endpoints, replaced by these two


# class based like the allauth views they replace, so HEAD and OPTIONS answer
# the same way


@method_decorator([never_cache, ensure_csrf_cookie], name="get")
class LoginConfig(View):
    def get(self, request):
        """Providers for the login page: id, name and icon only, none while SSO is
        off. Also sets the csrftoken cookie the login form posts back."""
        providers = _login_providers()
        return JsonResponse(
            {"status": 200, "data": {"socialaccount": {"providers": providers}}}
        )


def _login_providers() -> list:
    providers = []
    if sso_enabled():
        # code point order by name, as allauth sorted them, not the db collation
        apps = sorted(
            SocialApp.objects.filter(provider=PROVIDER).exclude(provider_id=""),
            key=lambda app: (app.name, app.pk),
        )
        # an ambiguous provider_id or a blocked issuer cannot sign in, so
        # neither is offered
        counts = Counter(app.provider_id for app in apps)
        providers = [
            {
                "id": app.provider_id,
                "name": app.name,
                "icon": provider_icon(provider_settings(app).get("server_url")),
            }
            for app in apps
            if counts[app.provider_id] == 1 and not issuer_problem(app)
        ]
    return providers


@method_decorator(csrf_protect, name="post")
class StartLogin(View):
    def post(self, request):
        """Form POST from the login page. Redirects to the IdP, or back to the
        dashboard callback page with ?error=."""
        return _start_login(request)


def _start_login(request):
    if (
        not sso_enabled()
        or request.POST.get("process") != AuthProcess.LOGIN
        or request.POST.get("callback_url") != login_callback_url()
    ):
        return login_error_redirect("unknown")

    app = _single_app(request.POST.get("provider", ""))
    if not app:
        return login_error_redirect("unknown")

    try:
        return app.get_provider(request).redirect(
            request,
            AuthProcess.LOGIN,
            next_url=login_callback_url(),
            headless=True,
            **{STATE_PROVIDER_KEY: app.provider_id},
        )
    except Exception as e:
        # discovery document unreachable, refused or malformed
        _audit_failed_sso(
            "unknown",
            f"provider {app.provider_id} could not be reached ({type(e).__name__})",
            {"ip": get_client_ip(request.META), "provider": app.provider_id},
        )
        return login_error_redirect("unknown")


def _redirect_error(response):
    if response.status_code != 302:
        return "unknown"
    query = parse_qs(urlsplit(response.get("Location", "")).query)
    return (query.get("error") or [""])[0]


def _state_matches(request, provider_id) -> bool:
    """False when the state names a login started at another provider.

    allauth looks the state up by id only, so without this a login started at
    one provider could finish at another one's callback. A mismatched state is
    consumed. An unknown state is left to allauth, which refuses it.
    """
    state_id = get_request_param(request, "state")
    entry = statekit.get_states(request).get(state_id)
    if entry is None:
        return True
    if entry[0].get(STATE_PROVIDER_KEY) == provider_id:
        return True
    states = statekit.get_states(request)
    states.pop(state_id, None)
    request.session[STATES_SESSION_KEY] = states
    return False


def provider_callback(request, provider_id):
    """The OIDC redirect URI. allauth completes the code exchange and signs the
    user in to the session; the dashboard then trades it for a token."""
    # only a browser that started a login here gets its failure audited
    started = bool(request.session.get(STATES_SESSION_KEY))

    refused = ""
    if not sso_enabled():
        refused = "SSO is disabled"
    elif not _single_app(provider_id):
        refused = f"provider {provider_id} is not configured"
    elif not _state_matches(request, provider_id):
        refused = f"the login was not started at provider {provider_id}"

    if refused:
        response = login_error_redirect("unknown")
    else:
        response = oidc_views.callback(request, provider_id=provider_id)

    error = _redirect_error(response)
    if response.status_code != 302:
        # a flow allauth would finish on one of its own pages
        response = login_error_redirect(error)
    if error:
        if started:
            _audit_failed_sso(
                "unknown",
                refused or f"provider {provider_id} returned {error}",
                {"ip": get_client_ip(request.META), "provider": provider_id},
            )
    elif request.user.is_authenticated:
        # the session only exists to be exchanged
        request.session.set_expiry(EXCHANGE_MAX_AGE)
    return response
