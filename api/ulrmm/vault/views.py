# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from cryptography.fernet import InvalidToken
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from clients.models import Client, Site
from core.utils import stepup_denied
from laps.models import after_reveal
from logs.models import AuditLog
from remote.utils import decrypt_secret
from ulrmm.constants import AGENT_DEFER, AuditActionType, AuditObjType
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info
from ulrmm.permissions import (
    _has_perm,
    _has_perm_on_agent,
    _has_perm_on_client,
    _has_perm_on_site,
)
from ulrmm.throttles import VaultRevealThrottle

from .models import HKDF_INFO, SCOPES, Credential, Document
from .serializers import CredentialSerializer, DocumentSerializer


class FlagPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, view.flag)


def _in_scope(user, item, *, manage: bool = False) -> bool:
    # site-restricted role reads the client's items. writes are on its sites and devices
    if item.client_id:
        return _has_perm_on_client(user, item.client_id, manage=manage)
    if item.site_id:
        return _has_perm_on_site(user, item.site_id)
    return _has_perm_on_agent(user, item.agent.agent_id)


def _rows(model, q: Q, order):
    return (
        model.objects.filter(q)
        .select_related("agent")
        .defer(*(f"agent__{f}" for f in AGENT_DEFER))
        .order_by(*order)
    )


class ScopeItems(APIView):
    """Items of one client, site or device.

    A device includes the items of its site and client. A site includes
    the items of its client.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, scope, key):
        docs = _has_perm(request, "can_list_agents")
        creds = _has_perm(request, "can_view_credentials")
        if not (docs or creds):
            raise PermissionDenied()

        user = request.user
        if scope == "client":
            client = get_object_or_404(Client, pk=key)
            allowed = _has_perm_on_client(user, client.pk)
            # a site-restricted role can read this client. it cannot write here
            writable = _has_perm_on_client(user, client.pk, manage=True)
            levels = [Q(client=client)]
        elif scope == "site":
            site = get_object_or_404(Site, pk=key)
            allowed = writable = _has_perm_on_site(user, site.pk)
            levels = [Q(site=site), Q(client_id=site.client_id)]
        else:
            agent = get_object_or_404(
                Agent.objects.defer(*AGENT_DEFER).select_related("site"),
                agent_id=key,
            )
            allowed = writable = _has_perm_on_agent(user, agent.agent_id)
            levels = [
                Q(agent=agent),
                Q(site_id=agent.site_id),
                Q(client_id=agent.site.client_id),
            ]
        if not allowed:
            raise PermissionDenied()

        ctx = {"scope": scope}
        documents = credentials = []
        if docs:
            documents = [
                d for q in levels for d in _rows(Document, q, ("-pinned", "title"))
            ]
        if creds:
            credentials = [c for q in levels for c in _rows(Credential, q, ("name",))]
        return Response(
            {
                "documents": DocumentSerializer(documents, many=True, context=ctx).data,
                "credentials": CredentialSerializer(
                    credentials, many=True, context=ctx
                ).data,
                # permissions on this scope. an empty list does not mean the section is hidden
                "can": {
                    "view_documents": bool(docs),
                    "view_credentials": bool(creds),
                    "manage_credentials": bool(
                        writable and _has_perm(request, "can_manage_credentials")
                    ),
                    "manage_documents": bool(
                        writable and _has_perm(request, "can_manage_notes")
                    ),
                },
            }
        )


class AddItem(APIView):
    permission_classes = [IsAuthenticated, FlagPerms]

    def post(self, request):
        s = self.serializer(data=request.data)
        s.is_valid(raise_exception=True)
        item = s.Meta.model(**{k: s.validated_data.get(k) for k in SCOPES})
        if not _in_scope(request.user, item, manage=True):
            raise PermissionDenied()
        return Response(self.serializer(s.save()).data)


class EditDeleteItem(APIView):
    permission_classes = [IsAuthenticated, FlagPerms]

    def _get(self, request, pk):
        item = get_object_or_404(self.serializer.Meta.model, pk=pk)
        if not _in_scope(request.user, item, manage=True):
            raise PermissionDenied()
        return item

    def put(self, request, pk):
        item = self._get(request, pk)
        s = self.serializer(instance=item, data=request.data, partial=True)
        s.is_valid(raise_exception=True)
        return Response(self.serializer(s.save()).data)

    def delete(self, request, pk):
        item = self._get(request, pk)
        item.delete()
        return Response(f"{item} was deleted")


class AddDocument(AddItem):
    flag = "can_manage_notes"
    serializer = DocumentSerializer


class EditDeleteDocument(EditDeleteItem):
    flag = "can_manage_notes"
    serializer = DocumentSerializer


class AddCredential(AddItem):
    flag = "can_manage_credentials"
    serializer = CredentialSerializer


class EditDeleteCredential(EditDeleteItem):
    flag = "can_manage_credentials"
    serializer = CredentialSerializer


class RevealCredential(APIView):
    permission_classes = [IsAuthenticated, FlagPerms]
    throttle_classes = [VaultRevealThrottle]
    flag = "can_view_credentials"

    def post(self, request, pk):
        cred = get_object_or_404(
            _rows(Credential, Q(pk=pk), ()).select_related("client", "site__client")
        )
        if not _in_scope(request.user, cred):
            raise PermissionDenied()
        if denied := stepup_denied(
            request,
            "Showing a stored secret needs the same 60 minute step-up as terminal "
            "and files.",
        ):
            return denied
        if not cred.secret:
            return notify_error("No secret is stored for this credential.")
        try:
            secret = decrypt_secret(cred.secret, HKDF_INFO)
        except InvalidToken:
            return notify_error("The secret can no longer be read, enter it again.")

        if cred.client_id:
            where = f"client {cred.client.name}"
        elif cred.site_id:
            where = f"site {cred.site.client.name} / {cred.site.name}"
        else:
            where = f"device {cred.agent.hostname}"
        AuditLog.objects.create(
            username=request.user.username,
            agent=cred.agent.hostname if cred.agent_id else None,
            agent_id=cred.agent.agent_id if cred.agent_id else None,
            object_type=AuditObjType.CREDENTIAL,
            action=AuditActionType.VIEW,
            message=f"{request.user.username} revealed credential {cred.name} of {where}",
            after_value={
                "credential": cred.pk,
                "name": cred.name,
                "scope": cred.scope,
                "client": cred.client_id,
                "site": cred.site_id,
                "agent": cred.agent.agent_id if cred.agent_id else None,
            },
            debug_info=get_debug_info(),
        )
        after_reveal(cred)
        r = Response({"secret": secret})
        r["Cache-Control"] = "no-store"
        return r
