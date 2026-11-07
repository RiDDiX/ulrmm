# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import uuid

from django.conf import settings
from django.db import transaction
from django.db.models import Count, Exists, OuterRef, Prefetch, Q
from django.http import HttpResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from knox.models import AuthToken
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import Role, User, drop_role_cache
from accounts.utils import (
    DELETE_NEEDS_TOTP,
    audit_role_scope,
    resolve_pk,
    verify_fresh_totp,
)
from agents.models import Agent
from automation.models import Policy
from core.models import CustomField
from core.utils import get_core_settings
from deploy import installers, signing
from logs.models import AuditLog
from ulrmm.constants import (
    ALL_TIMEZONES,
    AgentMonType,
    AuditActionType,
    AuditObjType,
    GoArch,
)
from ulrmm.helpers import get_client_ip, notify_error, save_or_update_existing
from ulrmm.permissions import (
    _has_perm,
    _has_perm_on_client,
    _has_perm_on_site,
    _may_assign_policy,
    _patch_policy_guard,
)
from ulrmm.throttles import _ClientIPAnonThrottle

from .models import (
    MAX_ENROLLMENTS,
    Client,
    ClientCustomField,
    Deployment,
    Site,
    SiteCustomField,
    _drop_policy_cache,
)
from .permissions import ClientsPerms, DeploymentPerms, SitesPerms
from .serializers import (
    ClientCustomFieldSerializer,
    ClientSerializer,
    DeploymentSerializer,
    SiteCustomFieldSerializer,
    SiteSerializer,
)

# body keys that can change which (patch) policy reaches the agents
POLICY_FIELDS = {"server_policy", "workstation_policy", "block_policy_inheritance"}
# install media (USB sticks) stay in use for months
DEPLOYMENT_MAX_TTL = dt.timedelta(days=365)
INVALID_REQUEST = "The request was invalid"


class _Refused(Exception):
    """Aborts the request's transaction with a 400 string."""


def _body(request) -> dict:
    return request.data if isinstance(request.data, dict) else {}


def _as_pk(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value)
    return None


def _is_scoped(user) -> bool:
    role = user.get_and_set_role_cache()
    if user.is_superuser or role is None or role.is_superuser:
        return False
    return bool(role.can_view_clients.all()) or bool(role.can_view_sites.all())


def _check_policy_choices(user, values: dict, instance=None) -> None:
    """A scoped role may hand its clients and sites only policies it can see
    (_may_assign_policy). The form re-sends the current policy on every edit;
    that is no assignment."""
    for key in ("server_policy", "workstation_policy"):
        policy = resolve_pk(Policy, values.get(key))
        if policy is None:
            # empty clears it, an unknown pk is the serializer's to report
            continue
        if instance is not None and policy.pk == getattr(instance, f"{key}_id"):
            continue
        if not _may_assign_policy(user, policy):
            raise _Refused("You cannot assign this policy.")


def _custom_field_rows(entries):
    if entries is None:
        return []
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise _Refused(INVALID_REQUEST)
    return entries


_CUSTOM_FIELD_KINDS = {
    "client": (ClientCustomField, ClientCustomFieldSerializer, "clients", False),
    "site": (SiteCustomField, SiteCustomFieldSerializer, "sites", True),
}


def _save_custom_fields(entries, kind: str, owner) -> None:
    model, serializer_class, label, partial = _CUSTOM_FIELD_KINDS[kind]
    for entry in entries:
        field = CustomField.objects.filter(pk=_as_pk(entry.get("field"))).first()
        if field is None:
            raise _Refused(INVALID_REQUEST)
        if field.model != kind:
            raise _Refused(f"This custom field does not belong to {label}")

        # one row per owner and field (unique constraint): update it if present
        row = model.objects.filter(field=field, **{kind: owner}).first()
        serializer = serializer_class(
            instance=row,
            data={**entry, kind: owner.pk},
            partial=partial and row is not None,
        )
        serializer.is_valid(raise_exception=True)
        save_or_update_existing(serializer, model, field=field, **{kind: owner})


def _grow_role_scope(user, attr: str, obj) -> None:
    """A scoped creator keeps seeing what it just created."""
    role = user.role
    if role is None or not getattr(role, attr).all():
        return
    before = role.serialize(role)
    getattr(role, attr).add(obj)
    audit_role_scope(role, before)


def _scope_roles(clients, sites):
    return Role.objects.filter(
        Q(can_view_clients__in=clients) | Q(can_view_sites__in=sites)
    ).distinct()


def _roles_left_unscoped(clients, sites) -> str:
    """Roles whose whole scope goes with these rows; an empty scope sees everything."""
    names = [
        role.name
        for role in _scope_roles(clients, sites)
        if not role.is_superuser
        and not role.can_view_clients.exclude(pk__in=clients).exists()
        and not role.can_view_sites.exclude(pk__in=sites).exists()
    ]
    if not names:
        return ""
    return (
        f"These roles are limited to what is being deleted and would see "
        f"everything afterwards: {', '.join(sorted(names))}. Change their scope first."
    )


def _filtered_sites(user):
    in_maintenance = Agent.objects.filter(site=OuterRef("pk"), maintenance_mode=True)
    sites = (
        Site.objects.order_by("name")
        .select_related("client")
        .filter_by_role(user)
        .prefetch_related("custom_fields__field")
        .annotate(maintenance_mode=Exists(in_maintenance), agent_count=Count("agents"))
    )
    return Prefetch("sites", queryset=sites, to_attr="filtered_sites")


def _clients_with_sites(user):
    return Client.objects.prefetch_related(
        Prefetch(
            "custom_fields", queryset=ClientCustomField.objects.select_related("field")
        ),
        _filtered_sites(user),
    )


def _move_agents(request, agents, target: Site) -> None:
    with _patch_policy_guard(request, agents):
        # queryset update skips Agent.save, so the alert template is
        # recomputed below and the policy merges dropped once committed
        agents.update(site=target)
    transaction.on_commit(_drop_policy_cache)


class GetAddClients(APIView):
    permission_classes = [IsAuthenticated, ClientsPerms]

    def get(self, request):
        clients = (
            _clients_with_sites(request.user)
            .order_by("name")
            .filter_by_role(request.user)
            .select_related("workstation_policy", "server_policy", "alert_template")
        )
        clients = list(clients)
        for client in clients:
            # over the sites this role sees, not over the whole client
            client.agent_count = sum(s.agent_count for s in client.filtered_sites)
            client.maintenance_mode = any(
                s.maintenance_mode for s in client.filtered_sites
            )
        return Response(ClientSerializer(clients, many=True).data)

    def post(self, request):
        data = _body(request)
        client_data, site_data = data.get("client"), data.get("site")
        if not isinstance(client_data, dict) or not isinstance(site_data, dict):
            return notify_error(INVALID_REQUEST)

        setup = None
        if "initialsetup" in data:
            # these are server-wide settings, not client data
            if not _has_perm(request, "can_edit_core_settings"):
                raise PermissionDenied()
            timezone, company = data.get("timezone"), data.get("companyname")
            if not isinstance(timezone, str) or timezone not in ALL_TIMEZONES:
                return notify_error("Unknown time zone")
            if not isinstance(company, str):
                return notify_error(INVALID_REQUEST)
            setup = (timezone, company)

        try:
            _check_policy_choices(request.user, client_data)
            entries = _custom_field_rows(data.get("custom_fields"))
            serializer = ClientSerializer(data=client_data)
            serializer.is_valid(raise_exception=True)

            with transaction.atomic():
                client = serializer.save()
                site = SiteSerializer(
                    data={"client": client.id, "name": site_data.get("name")}
                )
                site.is_valid(raise_exception=True)
                site.save()

                if setup:
                    core = get_core_settings()
                    core.default_time_zone, core.mesh_company_name = setup
                    core.save(update_fields=["default_time_zone", "mesh_company_name"])

                _save_custom_fields(entries, "client", client)
                _grow_role_scope(request.user, "can_view_clients", client)
        except _Refused as refused:
            return notify_error(str(refused))

        return Response(f"{client.name} was added")


class GetUpdateDeleteClient(APIView):
    permission_classes = [IsAuthenticated, ClientsPerms]

    def get(self, request, pk):
        client = get_object_or_404(_clients_with_sites(request.user), pk=pk)
        return Response(ClientSerializer(client).data)

    def put(self, request, pk):
        client = get_object_or_404(Client, pk=pk)
        data = _body(request)
        client_data = data.get("client")
        if not isinstance(client_data, dict):
            return notify_error(INVALID_REQUEST)

        try:
            _check_policy_choices(request.user, client_data, client)
            entries = _custom_field_rows(data.get("custom_fields"))
            serializer = ClientSerializer(
                instance=client, data=client_data, partial=True
            )
            serializer.is_valid(raise_exception=True)

            agents = Agent.objects.filter(site__client=client)
            if not POLICY_FIELDS & client_data.keys():
                agents = agents.none()

            with transaction.atomic():
                Client.objects.select_for_update().filter(pk=client.pk).first()
                with _patch_policy_guard(request, agents):
                    serializer.save()
                _save_custom_fields(entries, "client", client)
        except _Refused as refused:
            return notify_error(str(refused))

        # the literal braces are what the web has always received
        return Response("{client} was updated")

    def delete(self, request, pk):
        from alerts.tasks import cache_agents_alert_template

        client = get_object_or_404(Client, pk=pk)
        move_to = request.query_params.get("move_to_site")
        target = None

        if client.live_agent_count > 0:
            if not move_to:
                return notify_error(
                    "Agents exist under this client. There needs to be a site "
                    "specified to move existing agents to"
                )
            target = get_object_or_404(Site, pk=_as_pk(move_to))
            if not _has_perm_on_site(request.user, target.pk):
                raise PermissionDenied()
            if target.client_id == client.pk:
                return notify_error("Pick a site of another client.")

        clients = [client.pk]
        sites = list(client.sites.values_list("pk", flat=True))
        if unscoped := _roles_left_unscoped(clients, sites):
            return notify_error(unscoped)

        # single use, so checked after every other refusal
        if not verify_fresh_totp(request.user, _body(request).get("totp_code")):
            return notify_error(DELETE_NEEDS_TOTP)

        gone = f"{client.name} was deleted"
        with transaction.atomic():
            Client.objects.select_for_update().filter(pk=client.pk).first()
            # again under the lock: a role or site may have changed meanwhile
            sites = list(client.sites.values_list("pk", flat=True))
            if unscoped := _roles_left_unscoped(clients, sites):
                return notify_error(unscoped)
            agents = Agent.objects.filter(site__client=client)
            if target:
                _move_agents(request, agents, target)
            elif agents.exists():
                # an agent enrolled since the check above
                return notify_error(
                    "Agents exist under this client. There needs to be a site "
                    "specified to move existing agents to"
                )
            # the cascade does not send m2m_changed, so the cache is dropped here
            roles = list(_scope_roles(clients, sites).values_list("pk", flat=True))
            client.delete()
        drop_role_cache(roles)

        if target:
            cache_agents_alert_template.delay()
        return Response(gone)


class GetAddSites(APIView):
    permission_classes = [IsAuthenticated, SitesPerms]

    def get(self, request):
        sites = (
            Site.objects.filter_by_role(request.user)
            .select_related("client")
            .prefetch_related("custom_fields__field")
        )
        return Response(SiteSerializer(sites, many=True).data)

    def post(self, request):
        data = _body(request)
        site_data = data.get("site")
        # the scope is checked before anything else is looked at
        source = site_data if isinstance(site_data, dict) else data
        client_pk = _as_pk(source.get("client"))
        if client_pk is None:
            if _is_scoped(request.user):
                raise PermissionDenied()
            return notify_error(INVALID_REQUEST)
        if not _has_perm_on_client(request.user, client_pk):
            raise PermissionDenied()
        if not isinstance(site_data, dict):
            return notify_error(INVALID_REQUEST)

        try:
            _check_policy_choices(request.user, site_data)
            entries = _custom_field_rows(data.get("custom_fields"))
            serializer = SiteSerializer(data=site_data)
            serializer.is_valid(raise_exception=True)

            with transaction.atomic():
                site = serializer.save()
                _save_custom_fields(entries, "site", site)
                _grow_role_scope(request.user, "can_view_sites", site)
        except _Refused as refused:
            return notify_error(str(refused))

        return Response(f"Site {site.name} was added!")


class GetUpdateDeleteSite(APIView):
    permission_classes = [IsAuthenticated, SitesPerms]

    def get(self, request, pk):
        site = get_object_or_404(
            Site.objects.select_related("client").prefetch_related(
                "custom_fields__field"
            ),
            pk=pk,
        )
        return Response(SiteSerializer(site).data)

    def put(self, request, pk):
        site = get_object_or_404(Site.objects.select_related("client"), pk=pk)
        data = _body(request)
        site_data = data.get("site")
        if not isinstance(site_data, dict):
            return notify_error(INVALID_REQUEST)

        # resolved like the serializer does; a missing client is its 400
        new_client = resolve_pk(Client, site_data.get("client"))
        if new_client is not None and new_client.pk != site.client_id:
            # moving a site hands its agents to the other client's operators
            if not _has_perm_on_client(request.user, new_client.pk, manage=True):
                raise PermissionDenied()
            if site.client.sites.count() == 1:
                return notify_error("A client must have at least one site")

        try:
            _check_policy_choices(request.user, site_data, site)
            entries = _custom_field_rows(data.get("custom_fields"))
            serializer = SiteSerializer(instance=site, data=site_data, partial=True)
            serializer.is_valid(raise_exception=True)

            agents = Agent.objects.filter(site=site)
            if "client" not in site_data and not POLICY_FIELDS & site_data.keys():
                agents = agents.none()

            with transaction.atomic():
                Site.objects.select_for_update().filter(pk=site.pk).first()
                with _patch_policy_guard(request, agents):
                    serializer.save()
                _save_custom_fields(entries, "site", site)
        except _Refused as refused:
            return notify_error(str(refused))

        return Response("Site was edited")

    def delete(self, request, pk):
        from alerts.tasks import cache_agents_alert_template

        site = get_object_or_404(Site.objects.select_related("client"), pk=pk)
        if site.client.sites.count() == 1:
            return notify_error("A client must have at least 1 site.")

        move_to = request.query_params.get("move_to_site")
        target = None
        if site.live_agent_count > 0:
            if not move_to:
                return notify_error("Choose a site to move the agents to first.")
            target = get_object_or_404(Site, pk=_as_pk(move_to))
            if not _has_perm_on_site(request.user, target.pk):
                raise PermissionDenied()
            if target.pk == site.pk:
                return notify_error("Pick another site to move the agents to.")

        if unscoped := _roles_left_unscoped([], [site.pk]):
            return notify_error(unscoped)

        if not verify_fresh_totp(request.user, _body(request).get("totp_code")):
            return notify_error(DELETE_NEEDS_TOTP)

        with transaction.atomic():
            Site.objects.select_for_update().filter(pk=site.pk).first()
            if unscoped := _roles_left_unscoped([], [site.pk]):
                return notify_error(unscoped)
            agents = Agent.objects.filter(site=site)
            if target:
                _move_agents(request, agents, target)
            elif agents.exists():
                return notify_error("Choose a site to move the agents to first.")
            roles = list(_scope_roles([], [site.pk]).values_list("pk", flat=True))
            site.delete()
        drop_role_cache(roles)

        if target:
            cache_agents_alert_template.delay()
        return Response(f"{site.name} was deleted")


def _audit_deployment(
    request, action, site, message: str, value=None, before=None
) -> None:
    AuditLog.objects.create(
        username=request.user.username,
        object_type=AuditObjType.SITE,
        action=action,
        message=message,
        before_value=before,
        after_value=value,
        debug_info={"ip": getattr(request, "_client_ip", "")},
    )


def _deployment_rows(qs):
    return qs.select_related("site__client", "policy").annotate(
        enrollment_count=Count("enrollments")
    )


class AgentDeployment(APIView):
    """Lists and adds deployments on the collection path, deletes one on the
    detail path; anything else is answered with 405."""

    permission_classes = [IsAuthenticated, DeploymentPerms]

    def get(self, request, pk=None):
        if pk is not None:
            return self.http_method_not_allowed(request)
        deployments = _deployment_rows(
            Deployment.objects.filter_by_role(request.user)
        ).order_by("pk")
        return Response(DeploymentSerializer(deployments, many=True).data)

    def post(self, request, pk=None):
        if pk is not None:
            return self.http_method_not_allowed(request)
        if getattr(settings, "ULRMM_INSECURE", False):
            return notify_error("Not available in insecure mode")

        data = _body(request)
        site_pk = _as_pk(data.get("site"))
        if site_pk is None:
            return notify_error(INVALID_REQUEST)
        site = get_object_or_404(Site, pk=site_pk)
        if not _has_perm_on_site(request.user, site.pk):
            raise PermissionDenied()

        # enrollment runs as the installer user
        if not User.objects.filter(is_installer_user=True).exists():
            return notify_error(
                "No installer user exists. Run create_installer_user first."
            )

        now = djangotime.now()
        try:
            expires = dt.datetime.strptime(data["expires"], "%Y-%m-%dT%H:%M:%S%z")
        except Exception:
            return notify_error("expire date is invalid")
        if expires <= now:
            return notify_error("expire date is invalid")
        if expires - now > DEPLOYMENT_MAX_TTL:
            return notify_error("A deployment link can be valid for 365 days at most.")

        mon_type, goarch = data.get("agenttype"), data.get("goarch")
        flags = {key: data.get(key) for key in ("power", "ping", "rdp")}
        name = data.get("name") or ""
        if (
            mon_type not in AgentMonType.values
            or goarch not in GoArch.values
            or None in flags.values()
            or not isinstance(name, str)
            or len(name) > 100
            or not name.isprintable()
        ):
            return notify_error(INVALID_REQUEST)

        cap = data.get("max_enrollments")
        if cap is not None and (
            not isinstance(cap, int)
            or isinstance(cap, bool)
            or not 1 <= cap <= MAX_ENROLLMENTS
        ):
            return notify_error(
                f"max_enrollments must be empty or 1 to {MAX_ENROLLMENTS}"
            )

        policy = None
        if data.get("policy") not in (None, ""):
            policy_pk = _as_pk(data.get("policy"))
            policy = Policy.objects.filter(pk=policy_pk).first() if policy_pk else None
            if policy is None:
                return notify_error(INVALID_REQUEST)
            if not _may_assign_policy(request.user, policy):
                return notify_error("You cannot assign this policy.")

        # installers carry a signed enrollment token minted from this row
        with transaction.atomic():
            deployment = Deployment.objects.create(
                site=site,
                name=name.strip(),
                expiry=expires,
                mon_type=mon_type,
                goarch=goarch,
                policy=policy,
                install_flags={k: bool(v) for k, v in flags.items()},
                max_enrollments=cap,
            )
            _audit_deployment(
                request,
                AuditActionType.ADD,
                site,
                f"{request.user.username} added a deployment for site {site.name}",
                {
                    "mon_type": mon_type,
                    "goarch": goarch,
                    "expiry": expires.isoformat(),
                    "policy": policy.pk if policy else None,
                    "max_enrollments": cap,
                },
            )
        deployment = _deployment_rows(Deployment.objects).get(pk=deployment.pk)
        return Response(DeploymentSerializer(deployment).data, status=201)

    def delete(self, request, pk=None):
        if pk is None:
            return self.http_method_not_allowed(request)
        deployment = get_object_or_404(
            Deployment.objects.select_related("site__client"), pk=pk
        )
        if not _has_perm_on_site(request.user, deployment.site_id):
            raise PermissionDenied()

        site = deployment.site
        before = {
            "id": deployment.pk,
            "name": deployment.name,
            "client": site.client.name,
            "site": site.name,
            "expiry": deployment.expiry.isoformat() if deployment.expiry else None,
        }
        with transaction.atomic():
            # the install credential goes, and the deployment with it
            AuthToken.objects.filter(pk=deployment.auth_token_id).delete()
            deployment.delete()
            _audit_deployment(
                request,
                AuditActionType.DELETE,
                site,
                f"{request.user.username} deleted a deployment for site {site.name}",
                before=before,
            )
        return Response("The deployment was deleted")


class DeployDownloadThrottle(_ClientIPAnonThrottle):
    """Per client address and deployment, so a rollout behind one NAT address
    is not slowed down by its neighbours. Unknown links share the address's
    count. 600 an hour is 300 Linux hosts (sh and sig) or 600 Windows ones."""

    scope = "deploy_download"

    def get_cache_key(self, request, view):
        ident = self.get_ident(request)
        try:
            key = uuid.UUID(str(view.kwargs.get("uid")))
        except ValueError:
            key = None
        pk = key and Deployment.objects.filter(uid=key).values_list("pk").first()
        if pk:
            ident = f"{ident}-dep{pk[0]}"
        return self.cache_format % {"scope": self.scope, "ident": ident}


class GenerateAgent(APIView):
    """The public installer link of a deployment: ?fmt=exe|ps1|deb|rpm|tgz|
    sh|sig&arch=amd64|386|arm64|arm. The uid is the secret."""

    authentication_classes = []
    permission_classes = (AllowAny,)
    throttle_classes = [DeployDownloadThrottle]

    def get(self, request, uid):
        try:
            key = uuid.UUID(uid)
        except ValueError:
            key = None
        deployment = (
            Deployment.objects.select_related("site__client").filter(uid=key).first()
            if key
            else None
        )
        if deployment is None:
            return Response("This deployment does not exist.", status=404)
        if deployment.expiry is None or deployment.expiry <= djangotime.now():
            return Response("This deployment has expired.", status=410)

        fmt = request.query_params.get("fmt") or "exe"
        arch = request.query_params.get("arch") or None
        if fmt not in installers.ARCHES:
            return notify_error(f"fmt must be one of {', '.join(installers.ARCHES)}")
        # sh and sig without an arch pick the build by uname -m
        if arch is None and fmt not in ("sh", "sig"):
            arch = deployment.goarch
        if arch is not None and arch not in installers.ARCHES[fmt]:
            return notify_error(f"There is no {fmt} installer for {arch}.")
        if not signing.dist_pubkey_ok():
            return Response("agent build needed: run update.sh", status=503)

        signed = False
        try:
            if fmt == "exe":
                chunks, size, signed = installers.setup_exe(deployment, arch)
                response = StreamingHttpResponse(
                    chunks, content_type=installers.CONTENT_TYPES[fmt]
                )
                response["Content-Length"] = str(size)
                if not signed:
                    response["X-ULRMM-Unsigned"] = "1"
            else:
                response = HttpResponse(
                    installers.BUILDERS[fmt](deployment, arch),
                    content_type=installers.CONTENT_TYPES[fmt],
                )
        except installers.Unavailable as e:
            return Response(str(e), status=503)

        site = deployment.site
        AuditLog.objects.create(
            username="anonymous",
            object_type=AuditObjType.SITE,
            action=AuditActionType.AGENT_INSTALL,
            # never the uid, it is the link's secret
            message=(
                f"{fmt} installer ({arch or 'any arch'}) downloaded through "
                f"deployment {deployment.name or f'#{deployment.pk}'} for "
                f"{site.client.name} / {site.name}"
            ),
            after_value={
                "deployment": deployment.pk,
                "fmt": fmt,
                "arch": arch,
                "signed": signed,
            },
            debug_info={"ip": get_client_ip(request.META)},
        )
        name = installers.download_name(deployment, fmt, arch)
        response["Content-Disposition"] = f'attachment; filename="{name}"'
        response["Cache-Control"] = "no-store"
        return response
