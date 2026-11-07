# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime

import pyotp
from allauth.socialaccount.models import SocialApp
from django.contrib.auth import login
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from django.utils.crypto import get_random_string
from knox.models import AuthToken
from knox.views import LoginView as KnoxLoginView
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.tasks import sync_mesh_perms_task
from core.utils import get_core_settings
from logs.models import AuditLog
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.helpers import get_client_ip, notify_error
from ulrmm.mixins import GenericPermsViewMixin
from ulrmm.throttles import (
    CheckCredsDayThrottle,
    CheckCredsMinThrottle,
    LoginDayThrottle,
    LoginMinThrottle,
    StepUpMinThrottle,
)

from .models import APIKey, Role, User
from .permissions import (
    AccountsPerms,
    APIKeyPerms,
    LocalUserPerms,
    RolesPerms,
    SelfResetSSOPerms,
)
from .serializers import (
    APIKeySerializer,
    RoleSerializer,
    TOTPSetupSerializer,
    UserSerializer,
    UserUISerializer,
)
from .utils import (
    CHANGE_NEEDS_TOTP,
    TOTP_UNREADABLE_MSG,
    audit_role_scope,
    commit_pending_totp_key,
    console_stepup_remaining,
    drop_console_stepup,
    end_other_sessions,
    get_pending_totp_key,
    grant_console_stepup,
    has_superuser_rights,
    is_root_user,
    resolve_pk,
    set_pending_totp_key,
    totp_unreadable,
    verify_fresh_totp,
)

API_KEY_DEFAULT_TTL = datetime.timedelta(days=90)
CHECK_CREDS_TOKEN_TTL = datetime.timedelta(seconds=180)
# AuditLog.username and its message are 255 wide, the name is attacker input
AUDIT_NAME_MAX = 150

BAD_CREDENTIALS = "Bad credentials"
INVALID_REQUEST = "The request was invalid"
NEEDS_FRESH_CODE = (
    "Enter a current code from your authenticator app. "
    "If you just used one, wait for the next."
)
CHANGE_NEEDS_DASHBOARD = "Changing other accounts or roles needs a dashboard login."
# changing these on another account needs the actor's code
GUARDED_USER_FIELDS = ("role", "is_active", "block_dashboard_login")


def _body(request) -> dict:
    return request.data if isinstance(request.data, dict) else {}


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _as_pk(value):
    """A pk from a request body, or None when it cannot be one."""
    if _is_int(value):
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value)
    return None


def _audit_name(request) -> str:
    return str(_body(request).get("username", ""))[:AUDIT_NAME_MAX]


def _ip(request) -> dict:
    return {"ip": getattr(request, "_client_ip", "")}


def _local_logon_blocked(user) -> bool:
    # superusers keep the password login as their way back in
    return not has_superuser_rights(user) and get_core_settings().block_local_user_logon


def _accounts():
    # agent service users and the installer user are not managed here
    return User.objects.filter(agent__isnull=True, is_installer_user=False)


def _require_dashboard_code(request, code):
    """Changing your own login: a knox session, plus a fresh code when the
    account has TOTP. Returns an error response or None."""
    if not isinstance(request.auth, AuthToken):
        raise PermissionDenied("Changing your own login needs a dashboard login.")
    if request.user.totp_key and not verify_fresh_totp(request.user, code):
        return notify_error(NEEDS_FRESH_CODE)
    return None


def _require_actor_code(request):
    """Changes to other accounts and to roles need a fresh code of the actor,
    superusers included. Call it after every other refusal, a code works once.
    Returns an error response or None."""
    if isinstance(request.auth, APIKey):
        raise PermissionDenied(CHANGE_NEEDS_DASHBOARD)
    if not verify_fresh_totp(request.user, _body(request).get("totp_code")):
        return notify_error(CHANGE_NEEDS_TOTP)
    return None


_ROLE_FLAGS = tuple(
    field.name for field in Role._meta.concrete_fields if field.name.startswith("can_")
)


def _check_grant(request, values=None, role=None) -> None:
    """Without superuser rights only what the actor's own role holds can be
    handed out: its flags, and clients and sites inside its own scope.
    ``values`` are validated role fields, laid over ``role`` when given."""
    if has_superuser_rights(request.user):
        return
    own = request.user.role
    if own is None:
        raise PermissionDenied()
    values = values or {}

    def pick(name, current):
        return values[name] if name in values else current

    for flag in _ROLE_FLAGS:
        if pick(flag, getattr(role, flag, False)) and not getattr(own, flag):
            raise PermissionDenied(
                f"Your role does not have {flag}, so you cannot grant it."
            )

    own_clients = set(own.can_view_clients.values_list("pk", flat=True))
    own_sites = set(own.can_view_sites.values_list("pk", flat=True))
    if not own_clients and not own_sites:
        return
    clients = list(
        pick("can_view_clients", role.can_view_clients.all() if role else [])
    )
    sites = list(pick("can_view_sites", role.can_view_sites.all() if role else []))
    # a role without clients and sites reaches all of them
    inside = (
        bool(clients or sites)
        and all(client.pk in own_clients for client in clients)
        and all(s.pk in own_sites or s.client_id in own_clients for s in sites)
    )
    if not inside:
        raise PermissionDenied(
            "You can only grant clients and sites inside your own scope."
        )


def _check_target_grant(request, user) -> None:
    # acting on another login needs everything its role holds
    if user.pk != request.user.pk and user.role is not None:
        _check_grant(request, role=user.role)


def _keep_for(request, target):
    return request.auth if target.pk == request.user.pk else None


def _new_totp_key_for(user) -> str:
    # SSO accounts carry a random key nobody knows so the enrolment rules
    # never fire for them; a reset must not hand them an empty one
    return pyotp.random_base32() if user.is_sso_user else ""


def _end_dashboard_sessions(user) -> None:
    tokens = AuthToken.objects.filter(user=user)
    digests = list(tokens.values_list("digest", flat=True))
    tokens.delete()
    drop_console_stepup(user, digests)


def _active_super(user) -> bool:
    return (
        user.is_active and not user.block_dashboard_login and has_superuser_rights(user)
    )


def _other_active_superuser_exists(user) -> bool:
    return (
        _accounts()
        .filter(is_active=True, block_dashboard_login=False)
        .filter(Q(is_superuser=True) | Q(role__is_superuser=True))
        .exclude(pk=user.pk)
        .exists()
    )


class CheckCredsV2(KnoxLoginView):
    # no authentication: the per-IP throttles only key anonymous requests
    authentication_classes = ()
    permission_classes = (AllowAny,)
    throttle_classes = (CheckCredsMinThrottle, CheckCredsDayThrottle)

    def get_token_ttl(self):
        return CHECK_CREDS_TOKEN_TTL

    def post(self, request, format=None):
        creds = AuthTokenSerializer(data=request.data)
        if not creds.is_valid():
            AuditLog.audit_user_failed_login(
                _audit_name(request), debug_info=_ip(request)
            )
            return notify_error(BAD_CREDENTIALS)

        user = creds.validated_data["user"]
        if user.block_dashboard_login or user.is_sso_user:
            return notify_error(BAD_CREDENTIALS)
        if _local_logon_blocked(user):
            return notify_error(BAD_CREDENTIALS)
        if totp_unreadable(user):
            return notify_error(TOTP_UNREADABLE_MSG)

        if user.totp_key:
            return Response({"totp": True})

        # a short session that only reaches the enrolment endpoints
        login(request, user)
        response = super().post(request, format=format)
        response.data["totp"] = False
        return response


class LoginViewV2(KnoxLoginView):
    authentication_classes = ()
    permission_classes = (AllowAny,)
    throttle_classes = (LoginMinThrottle, LoginDayThrottle)

    def post(self, request, format=None):
        creds = AuthTokenSerializer(data=request.data)
        if not creds.is_valid():
            AuditLog.audit_user_failed_login(
                _audit_name(request), debug_info=_ip(request)
            )
            return Response(creds.errors, status=400)

        user = creds.validated_data["user"]
        if user.block_dashboard_login:
            return notify_error(BAD_CREDENTIALS)
        if _local_logon_blocked(user) or user.is_sso_user:
            return notify_error(BAD_CREDENTIALS)
        if totp_unreadable(user):
            AuditLog.audit_user_failed_twofactor(
                _audit_name(request), debug_info=_ip(request)
            )
            return notify_error(TOTP_UNREADABLE_MSG)

        pending = "" if user.totp_key else get_pending_totp_key(user)
        code = _body(request).get("twofactor")
        valid = verify_fresh_totp(user, code, pending) and (
            not pending or commit_pending_totp_key(user, pending)
        )
        if not valid:
            AuditLog.audit_user_failed_twofactor(
                _audit_name(request), debug_info=_ip(request)
            )
            return notify_error(BAD_CREDENTIALS)

        login(request, user)
        address = get_client_ip(request.META)
        if address:
            user.last_login_ip = address
            user.save(update_fields=["last_login_ip"])
        AuditLog.audit_user_login_successful(
            _audit_name(request), debug_info=_ip(request)
        )

        response = super().post(request, format=format)
        response.data["username"] = request.user.username
        response.data["name"] = None
        return response


def _social_display(account, apps) -> str:
    if account.provider not in apps:
        return "Orphaned Provider"
    app = apps[account.provider]
    if app is None:
        return "Unknown"
    try:
        return app.get_provider(None).wrap_account(account).to_str()
    except SocialApp.DoesNotExist:
        return app.name


def _sso_apps() -> dict:
    apps: dict = {}
    for app in SocialApp.objects.filter(provider="openid_connect"):
        # two apps answering to one provider id cannot be told apart
        apps[app.provider_id] = None if app.provider_id in apps else app
    return apps


class GetAddUsers(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    def get(self, request):
        users = _accounts().order_by("pk").prefetch_related("socialaccount_set")
        search = request.query_params.get("search")
        if search:
            users = users.filter(username__icontains=search)

        apps = _sso_apps()
        rows = []
        for user in users:
            row = UserSerializer(user).data
            # never the IdP claims (extra_data)
            row["social_accounts"] = [
                {
                    "uid": account.uid,
                    "provider": account.provider,
                    "display": _social_display(account, apps),
                    "last_login": account.last_login,
                    "date_joined": account.date_joined,
                }
                for account in user.socialaccount_set.all()
            ]
            rows.append(row)
        return Response(rows)

    def post(self, request):
        data = _body(request)
        username = data.get("username")
        password = data.get("password")
        email = data.get("email")
        names = {k: data[k] for k in ("first_name", "last_name") if k in data}
        # the Add User form offers both; they only ever narrow access
        access = {
            k: data[k]
            for k in ("is_active", "block_dashboard_login")
            if isinstance(data.get(k), bool)
        }
        texts = (username, password, email, *names.values())
        if not username or not all(isinstance(v, str) for v in texts):
            return notify_error(INVALID_REQUEST)

        try:
            # the model field validators also carry the max_length rules
            for field, value in (
                ("username", username),
                ("email", email),
                *names.items(),
            ):
                User._meta.get_field(field).run_validators(value)
            validate_password(password, User(username=username, email=email))
        except ValidationError as e:
            return notify_error(" ".join(e.messages))

        role = None
        if _is_int(data.get("role")):
            role = get_object_or_404(Role, pk=data["role"])
            if role.is_superuser and not has_superuser_rights(request.user):
                raise PermissionDenied("Only superusers can assign a superuser role.")
            _check_grant(request, role=role)
            error = _require_actor_code(request)
            if error:
                return error

        try:
            with transaction.atomic():
                user = User.objects.create_user(username, email, password)
                for key, value in (*names.items(), *access.items()):
                    setattr(user, key, value)
                if role:
                    user.role = role
                user.save()
        except IntegrityError:
            return notify_error(f"ERROR: User {username} already exists!")

        sync_mesh_perms_task.delay()
        return Response(user.get_username())


class GetUpdateDeleteUser(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    def get(self, request, pk):
        user = get_object_or_404(_accounts(), pk=pk)
        return Response(UserSerializer(user).data)

    def put(self, request, pk):
        user = get_object_or_404(_accounts(), pk=pk)
        if is_root_user(request=request, user=user):
            return notify_error("The root user cannot be modified from the UI")
        if not isinstance(request.data, dict):
            return notify_error(INVALID_REQUEST)
        data = request.data

        if not has_superuser_rights(request.user):
            self._check_limited_editor(request, user, data)
        _check_target_grant(request, user)

        serializer = UserSerializer(instance=user, data=data, partial=True)
        serializer.is_valid(raise_exception=True)

        changes = serializer.validated_data
        was_super = _active_super(user)
        role_after = changes.get("role", user.role)
        if role_after is not None and role_after != user.role:
            _check_grant(request, role=role_after)
        super_after = (
            changes.get("is_active", user.is_active)
            and not changes.get("block_dashboard_login", user.block_dashboard_login)
            and (user.is_superuser or bool(role_after and role_after.is_superuser))
        )
        if was_super and not super_after and not _other_active_superuser_exists(user):
            return notify_error("At least one active superuser has to remain.")

        if user.pk != request.user.pk and any(
            field in changes and changes[field] != getattr(user, field)
            for field in GUARDED_USER_FIELDS
        ):
            error = _require_actor_code(request)
            if error:
                return error

        locked_out = (user.is_active and changes.get("is_active") is False) or (
            not user.block_dashboard_login and changes.get("block_dashboard_login")
        )
        with transaction.atomic():
            serializer.save()
            if locked_out:
                # an auto-refreshing knox token would otherwise outlive the block
                _end_dashboard_sessions(user)

        sync_mesh_perms_task.delay()
        return Response("ok")

    @staticmethod
    def _check_limited_editor(request, user, data) -> None:
        if has_superuser_rights(user):
            raise PermissionDenied("Only superusers can modify superuser accounts.")

        role = resolve_pk(Role, data.get("role"))
        if role is not None and role.is_superuser:
            raise PermissionDenied("Only superusers can assign a superuser role.")

        if user.pk == request.user.pk:
            current = {
                "role": user.role_id,
                "block_dashboard_login": user.block_dashboard_login,
                "is_active": user.is_active,
            }
            sent = {field: data[field] for field in current if field in data}
            if "role" in sent:
                sent["role"] = role.pk if role else None
            for field, value in current.items():
                if field in sent and sent[field] != value:
                    raise PermissionDenied(f"You cannot change your own {field}.")

    def delete(self, request, pk):
        user = get_object_or_404(_accounts(), pk=pk)
        if is_root_user(request=request, user=user):
            return notify_error("The root user cannot be deleted from the UI")
        if has_superuser_rights(user) and not has_superuser_rights(request.user):
            raise PermissionDenied("Only superusers can delete superuser accounts.")
        _check_target_grant(request, user)
        if _active_super(user) and not _other_active_superuser_exists(user):
            return notify_error("At least one active superuser has to remain.")

        with transaction.atomic():
            user.delete()

        sync_mesh_perms_task.delay()
        return Response("ok")


def _check_session_boundary(request, user) -> None:
    if has_superuser_rights(user) and not has_superuser_rights(request.user):
        raise PermissionDenied("Only superusers can manage superuser sessions.")
    _check_target_grant(request, user)


def _audit_session_end(request, user) -> None:
    AuditLog.objects.create(
        username=request.user.username,
        object_type=AuditObjType.USER,
        action=AuditActionType.DELETE,
        message=f"{request.user.username} ended a session of {user.username}",
        debug_info=_ip(request),
    )


def _user_sessions(user):
    # install credentials of the installer user are never sessions
    return AuthToken.objects.filter(
        user=user,
        expiry__gt=djangotime.now(),
        deploytokens__isnull=True,
        installertokens__isnull=True,
    )


class DeleteActiveLoginSession(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    def delete(self, request, pk):
        token = get_object_or_404(
            AuthToken.objects.select_related("user").filter(
                user__agent__isnull=True,
                user__is_installer_user=False,
                deploytokens__isnull=True,
                installertokens__isnull=True,
            ),
            digest=pk,
        )
        user = token.user
        _check_session_boundary(request, user)

        token.delete()
        drop_console_stepup(user, [pk])
        _audit_session_end(request, user)
        return Response("ok")


class GetDeleteActiveLoginSessionsPerUser(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    def get(self, request, pk):
        user = get_object_or_404(_accounts(), pk=pk)
        _check_session_boundary(request, user)

        sessions = _user_sessions(user).order_by("created")
        return Response(
            [
                {
                    "digest": token.digest,
                    "user": user.username,
                    "created": token.created,
                    "expiry": token.expiry,
                }
                for token in sessions
            ]
        )

    def delete(self, request, pk):
        user = get_object_or_404(_accounts(), pk=pk)
        _check_session_boundary(request, user)

        with transaction.atomic():
            sessions = _user_sessions(user)
            digests = list(sessions.values_list("digest", flat=True))
            AuthToken.objects.filter(digest__in=digests).delete()
            for _ in digests:
                _audit_session_end(request, user)
        drop_console_stepup(user, digests)
        return Response("ok")


class UserActions(APIView):
    """Admin reset of a password (POST) or of the TOTP key (PUT)."""

    permission_classes = [IsAuthenticated, AccountsPerms, LocalUserPerms]
    # read by AccountsPerms: anyone may reset their own login here
    allows_self_service = True

    def _target(self, request):
        data = _body(request)
        pk = _as_pk(data.get("id"))
        if pk is None:
            return None, notify_error(INVALID_REQUEST)

        user = get_object_or_404(_accounts(), pk=pk)
        if is_root_user(request=request, user=user):
            return None, notify_error("The root user cannot be modified from the UI")

        if user.pk != request.user.pk:
            if has_superuser_rights(user) and not has_superuser_rights(request.user):
                raise PermissionDenied("Only superusers can reset superuser accounts.")
            _check_target_grant(request, user)
            return user, None

        return user, _require_dashboard_code(request, data.get("code"))

    @staticmethod
    def _code_for_other(request, user):
        # your own reset had its code checked in _target
        if user.pk == request.user.pk:
            return None
        return _require_actor_code(request)

    def post(self, request):
        user, error = self._target(request)
        if error:
            return error

        password = _body(request).get("password")
        if not isinstance(password, str):
            return notify_error(INVALID_REQUEST)
        try:
            validate_password(password, user)
        except ValidationError as e:
            return notify_error(" ".join(e.messages))
        error = self._code_for_other(request, user)
        if error:
            return error

        with transaction.atomic():
            user.set_password(password)
            user.save()
            end_other_sessions(user, keep=_keep_for(request, user))
        return Response("ok")

    def put(self, request):
        user, error = self._target(request)
        if error:
            return error
        error = self._code_for_other(request, user)
        if error:
            return error

        with transaction.atomic():
            user.totp_key = _new_totp_key_for(user)
            user.save()
            end_other_sessions(user, keep=_keep_for(request, user))
        return Response(
            f"Two-factor key of {user.username} reset. They set it up again at their next sign-in."
        )


class TOTPSetup(GenericPermsViewMixin, APIView):
    def post(self, request):
        user = request.user
        if totp_unreadable(user):
            return notify_error(TOTP_UNREADABLE_MSG)
        if user.totp_key:
            return Response(False)

        # held back until /v2/login/ sees the first code made with it
        key = pyotp.random_base32()
        set_pending_totp_key(user, key)
        if isinstance(request.auth, AuthToken):
            request.auth.delete()
        return Response(TOTPSetupSerializer(user, context={"totp_key": key}).data)


class ConsoleStepUp(GenericPermsViewMixin, APIView):
    throttle_classes = [StepUpMinThrottle]

    def get_throttles(self):
        # the countdown poll is free, only code attempts count
        if self.request.method != "POST":
            return []
        return super().get_throttles()

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if not isinstance(request.auth, AuthToken):
            raise PermissionDenied("Terminal and file access need a dashboard login.")

    def get(self, request):
        return Response({"remaining": console_stepup_remaining(request.user)})

    def post(self, request):
        user = request.user
        ok = verify_fresh_totp(user, _body(request).get("code"))
        if ok:
            message = f"{user.username} unlocked terminal and file access"
        else:
            message = (
                f"{user.username} failed to unlock terminal and file access: "
                "Two Factor token rejected"
            )
        AuditLog.objects.create(
            username=user.username,
            object_type=AuditObjType.USER,
            action=AuditActionType.LOGIN if ok else AuditActionType.FAILED_LOGIN,
            message=message,
            debug_info=_ip(request),
        )
        if not ok:
            return notify_error("The code was not accepted. Wait for the next one.")

        grant_console_stepup(user)
        return Response({"remaining": console_stepup_remaining(user)})


class UserUI(GenericPermsViewMixin, APIView):
    def patch(self, request):
        serializer = UserUISerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response("ok")


_ROLE_SCOPE = ("can_view_clients", "can_view_sites")


def _save_role(serializer, instance=None) -> Role:
    """Saves scalar columns and scope together, so the audit row shows the
    scope as it was before and after (DRF sets M2M only after the save)."""
    values = dict(serializer.validated_data)
    scope = {name: values.pop(name) for name in _ROLE_SCOPE if name in values}

    with transaction.atomic():
        if instance is None:
            role = Role(**values)
            role.save()
            before = Role.serialize(role)
            for name, items in scope.items():
                getattr(role, name).set(items)
            audit_role_scope(role, before)
            return role

        old = Role.objects.prefetch_related(*_ROLE_SCOPE).get(pk=instance.pk)
        for name, value in values.items():
            setattr(instance, name, value)
        for name, items in scope.items():
            getattr(instance, name).set(items)
        instance.save(old_model=old)
        return instance


def _check_can_manage_role(request, role, *, granting: bool) -> None:
    if has_superuser_rights(request.user):
        return
    if granting or role.is_superuser:
        raise PermissionDenied("Only superusers can manage superuser roles.")
    if request.user.role_id == role.pk:
        raise PermissionDenied("You cannot change the role you are assigned to.")


class GetAddRoles(APIView):
    permission_classes = [IsAuthenticated, RolesPerms]

    def get(self, request):
        roles = Role.objects.order_by("pk").prefetch_related(*_ROLE_SCOPE)
        return Response(RoleSerializer(roles, many=True).data)

    def post(self, request):
        data = _body(request)
        if data.get("is_superuser") and not has_superuser_rights(request.user):
            raise PermissionDenied("Only superusers can create superuser roles.")

        serializer = RoleSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        _check_grant(request, serializer.validated_data)
        error = _require_actor_code(request)
        if error:
            return error
        _save_role(serializer)
        return Response("Role was added")


class GetUpdateDeleteRole(APIView):
    permission_classes = [IsAuthenticated, RolesPerms]

    def get(self, request, pk):
        return Response(RoleSerializer(get_object_or_404(Role, pk=pk)).data)

    def put(self, request, pk):
        role = get_object_or_404(Role, pk=pk)
        data = _body(request)
        _check_can_manage_role(request, role, granting=bool(data.get("is_superuser")))

        serializer = RoleSerializer(instance=role, data=data)
        serializer.is_valid(raise_exception=True)
        _check_grant(request, serializer.validated_data, role)
        error = _require_actor_code(request)
        if error:
            return error
        _save_role(serializer, role)

        sync_mesh_perms_task.delay()
        return Response("Role was edited")

    def delete(self, request, pk):
        role = get_object_or_404(Role, pk=pk)
        _check_can_manage_role(request, role, granting=False)
        if role.users.exists():
            return notify_error(
                "This role is still assigned to users. Unassign it first."
            )
        error = _require_actor_code(request)
        if error:
            return error

        role.delete()
        sync_mesh_perms_task.delay()
        return Response("Role was removed")


def _refuse_service_owner(serializer):
    owner = serializer.validated_data.get("user")
    if owner is not None and (owner.agent_id or owner.is_installer_user):
        return notify_error("API keys cannot belong to agent or installer accounts.")
    return None


class GetAddAPIKeys(APIView):
    permission_classes = [IsAuthenticated, APIKeyPerms]

    def get(self, request):
        apikeys = APIKey.objects.order_by("pk").select_related("user")
        return Response(APIKeySerializer(apikeys, many=True).data)

    def post(self, request):
        data = _body(request)
        if (
            not has_superuser_rights(request.user)
            and data.get("user") != request.user.pk
        ):
            raise PermissionDenied("You can only create API keys for your own account.")

        serializer = APIKeySerializer(data=data)
        serializer.is_valid(raise_exception=True)
        error = _refuse_service_owner(serializer)
        if not error and serializer.validated_data["user"].pk != request.user.pk:
            error = _require_actor_code(request)
        if error:
            return error

        # the only moment the plaintext exists; the model stores its sha256
        key = get_random_string(length=32).upper()
        expiration = (
            serializer.validated_data.get("expiration")
            or djangotime.now() + API_KEY_DEFAULT_TTL
        )
        instance = serializer.save(key=key, expiration=expiration)
        return Response({**APIKeySerializer(instance).data, "key": key})


class GetUpdateDeleteAPIKey(APIView):
    permission_classes = [IsAuthenticated, APIKeyPerms]

    def put(self, request, pk):
        apikey = get_object_or_404(APIKey, pk=pk)
        data = _body(request)
        if not has_superuser_rights(request.user):
            owner = data.get("user", request.user.pk)
            if apikey.user_id != request.user.pk or owner != request.user.pk:
                raise PermissionDenied(
                    "You can only change API keys of your own account."
                )

        serializer = APIKeySerializer(instance=apikey, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        error = _refuse_service_owner(serializer)
        owner = serializer.validated_data.get("user", apikey.user)
        if not error and {apikey.user_id, owner.pk} != {request.user.pk}:
            error = _require_actor_code(request)
        if error:
            return error

        extra = {}
        if "expiration" in serializer.validated_data:
            # clearing the date restarts the default lifetime, never "forever"
            if serializer.validated_data["expiration"] is None:
                extra["expiration"] = djangotime.now() + API_KEY_DEFAULT_TTL
        serializer.save(**extra)
        return Response("API key updated")

    def delete(self, request, pk):
        apikey = get_object_or_404(APIKey, pk=pk)
        if not has_superuser_rights(request.user) and apikey.user_id != request.user.pk:
            raise PermissionDenied("You can only delete API keys of your own account.")
        if apikey.user_id != request.user.pk:
            error = _require_actor_code(request)
            if error:
                return error

        apikey.delete()
        return Response("API key deleted.")


class ResetPass(APIView):
    permission_classes = [IsAuthenticated, SelfResetSSOPerms]

    def put(self, request):
        data = _body(request)
        error = _require_dashboard_code(request, data.get("code"))
        if error:
            return error

        user = request.user
        password = data.get("password")
        if not isinstance(password, str):
            return notify_error(INVALID_REQUEST)
        try:
            validate_password(password, user)
        except ValidationError as e:
            return notify_error(" ".join(e.messages))

        with transaction.atomic():
            user.set_password(password)
            user.save()
            end_other_sessions(user, keep=request.auth)
        return Response("Password was reset.")


class Reset2FA(APIView):
    permission_classes = [IsAuthenticated, SelfResetSSOPerms]

    def put(self, request):
        error = _require_dashboard_code(request, _body(request).get("code"))
        if error:
            return error

        user = request.user
        with transaction.atomic():
            user.totp_key = ""
            user.save()
            end_other_sessions(user, keep=request.auth)
        return Response("2FA has been reset. Sign out and sign in again to set it up.")
