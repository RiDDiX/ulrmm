# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
from typing import Optional

from django.contrib.auth.models import AbstractUser
from django.core.cache import cache
from django.db import models
from django.db.models.signals import m2m_changed, post_delete, post_save
from django.dispatch import receiver

from core.models import EncryptedTextField
from logs.models import BaseAuditModel
from ulrmm.constants import (
    ROLE_CACHE_PREFIX,
    AgentDblClick,
    AgentTableTabs,
    ClientTreeSort,
)

ROLE_CACHE_TTL = 600
# never change: stored TOTP secrets could no longer be decrypted
TOTP_KEY_INFO = b"accounts.User.totp_key"
# a stored key no field key opens: two-factor stays required and cannot pass
# until an administrator resets it. Not base32, so it never works as a key.
TOTP_UNREADABLE = "!unreadable"


def _flag():
    return models.BooleanField(default=False)


class User(AbstractUser, BaseAuditModel):
    # redeclared without verbose_name/help_text, the migration state has neither
    is_active = models.BooleanField(default=True)
    block_dashboard_login = models.BooleanField(default=False)
    totp_key = EncryptedTextField(
        null=True, blank=True, hkdf_info=TOTP_KEY_INFO, unreadable=TOTP_UNREADABLE
    )
    dark_mode = models.BooleanField(default=True)
    show_community_scripts = models.BooleanField(default=True)
    agent_dblclick_action = models.CharField(
        max_length=50,
        choices=AgentDblClick.choices,
        default=AgentDblClick.DEVICE_PAGE,
    )
    url_action = models.ForeignKey(
        "core.URLAction",
        related_name="user",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    default_agent_tbl_tab = models.CharField(
        max_length=50, choices=AgentTableTabs.choices, default=AgentTableTabs.MIXED
    )
    agents_per_page = models.PositiveIntegerField(default=50)
    client_tree_sort = models.CharField(
        max_length=50, choices=ClientTreeSort.choices, default=ClientTreeSort.ALPHA_FAIL
    )
    client_tree_splitter = models.PositiveIntegerField(default=11)
    loading_bar_color = models.CharField(max_length=255, default="red")
    dash_info_color = models.CharField(max_length=255, default="info")
    dash_positive_color = models.CharField(max_length=255, default="positive")
    dash_negative_color = models.CharField(max_length=255, default="negative")
    dash_warning_color = models.CharField(max_length=255, default="warning")
    clear_search_when_switching = models.BooleanField(default=True)
    date_format = models.CharField(max_length=30, blank=True, null=True)
    is_installer_user = models.BooleanField(default=False)
    dashboard_layout = models.JSONField(default=dict, blank=True)
    last_login_ip = models.GenericIPAddressField(default=None, blank=True, null=True)
    agent = models.OneToOneField(
        "agents.Agent",
        related_name="user",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )
    role = models.ForeignKey(
        "accounts.Role",
        null=True,
        blank=True,
        related_name="users",
        on_delete=models.SET_NULL,
    )

    @property
    def mesh_username(self) -> str:
        # MeshCentral accounts are keyed on this, it must never change
        name = self.username.replace(" ", "").lower()
        return f"{name}___{self.pk}"

    @property
    def mesh_user_id(self) -> str:
        return f"user//{self.mesh_username}"

    @property
    def is_sso_user(self) -> bool:
        from allauth.socialaccount.models import SocialAccount

        return SocialAccount.objects.filter(user_id=self.pk).exists()

    @staticmethod
    def serialize(user):
        from . import serializers

        return serializers.UserSerializer(user).data

    def get_and_set_role_cache(self) -> "Optional[Role]":
        if not self.role_id:
            return None
        key = f"{ROLE_CACHE_PREFIX}{self.role_id}"
        role = cache.get(key)
        if isinstance(role, Role):
            return role
        role = self.role
        if role is None:
            return None
        models.prefetch_related_objects([role], "can_view_clients", "can_view_sites")
        cache.set(key, role, ROLE_CACHE_TTL)
        return role


class Role(BaseAuditModel):
    name = models.CharField(max_length=255, unique=True)
    is_superuser = _flag()
    can_view_clients = models.ManyToManyField(
        "clients.Client", related_name="role_clients", blank=True
    )
    can_view_sites = models.ManyToManyField(
        "clients.Site", related_name="role_sites", blank=True
    )

    # agents
    can_list_agents = _flag()
    can_use_mesh = _flag()
    can_uninstall_agents = _flag()
    can_update_agents = _flag()
    can_edit_agent = _flag()
    can_manage_procs = _flag()
    can_view_eventlogs = _flag()
    can_send_cmd = _flag()
    can_reboot_agents = _flag()
    can_install_agents = _flag()
    can_run_scripts = _flag()
    can_run_bulk = _flag()
    can_recover_agents = _flag()
    can_list_agent_history = _flag()
    can_send_wol = _flag()
    can_use_registry = _flag()
    can_use_terminal = _flag()

    # core
    can_list_notes = _flag()
    can_manage_notes = _flag()
    can_view_core_settings = _flag()
    can_edit_core_settings = _flag()
    can_do_server_maint = _flag()
    can_run_urlactions = _flag()
    can_view_customfields = _flag()
    can_manage_customfields = _flag()
    can_run_server_scripts = _flag()
    can_use_webterm = _flag()
    can_view_global_keystore = _flag()
    can_edit_global_keystore = _flag()
    can_view_schedules = _flag()
    can_manage_schedules = _flag()

    # checks
    can_list_checks = _flag()
    can_manage_checks = _flag()
    can_run_checks = _flag()

    # clients and sites
    can_list_clients = _flag()
    can_manage_clients = _flag()
    can_list_sites = _flag()
    can_manage_sites = _flag()
    can_list_deployments = _flag()
    can_manage_deployments = _flag()
    can_list_network_devices = _flag()
    can_manage_network_devices = _flag()

    # automation
    can_list_automation_policies = _flag()
    can_manage_automation_policies = _flag()

    # tasks
    can_list_autotasks = _flag()
    can_manage_autotasks = _flag()
    can_run_autotasks = _flag()

    # logs
    can_view_auditlogs = _flag()
    can_list_pendingactions = _flag()
    can_manage_pendingactions = _flag()
    can_view_debuglogs = _flag()

    # scripts
    can_list_scripts = _flag()
    can_manage_scripts = _flag()

    # alerts
    can_list_alerts = _flag()
    can_manage_alerts = _flag()
    can_list_alerttemplates = _flag()
    can_manage_alerttemplates = _flag()

    # services, software, updates
    can_manage_winsvcs = _flag()
    can_list_software = _flag()
    can_manage_software = _flag()
    can_manage_winupdates = _flag()

    # patches
    can_view_patches = _flag()
    can_approve_patches = _flag()
    can_install_patches_now = _flag()
    can_manage_patch_policies = _flag()
    can_enable_unofficial_sources = _flag()

    # fleet features
    can_manage_packages = _flag()
    can_manage_device_groups = _flag()
    can_run_network_discovery = _flag()
    can_view_vulnerabilities = _flag()
    can_view_credentials = _flag()
    can_manage_credentials = _flag()
    can_view_recovery_keys = _flag()
    can_install_packages = _flag()
    can_manage_laps = _flag()
    can_manage_integrations = _flag()
    can_manage_app_updates = _flag()
    can_manage_notifications = _flag()

    # accounts
    can_list_accounts = _flag()
    can_manage_accounts = _flag()
    can_list_roles = _flag()
    can_manage_roles = _flag()
    can_list_api_keys = _flag()
    can_manage_api_keys = _flag()

    # reporting
    can_view_reports = _flag()
    can_manage_reports = _flag()

    # server
    can_manage_server_updates = _flag()

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(role):
        from . import serializers

        return serializers.RoleAuditSerializer(role).data


def drop_role_cache(pks) -> None:
    keys = [f"{ROLE_CACHE_PREFIX}{pk}" for pk in pks if pk]
    if keys:
        cache.delete_many(keys)


@receiver(post_save, sender=Role, dispatch_uid="role_cache_saved")
@receiver(post_delete, sender=Role, dispatch_uid="role_cache_deleted")
def _role_row_changed(sender, instance, **kwargs) -> None:
    drop_role_cache([instance.pk])


def _role_scope_changed(sender, instance, action, reverse, pk_set, **kwargs) -> None:
    if not reverse:
        if action.startswith("post_"):
            drop_role_cache([instance.pk])
        return
    # changed from the client/site side: the roles are in pk_set, except for
    # clear, where they have to be read before the rows go
    if action == "pre_clear":
        owner = instance._meta.model_name
        drop_role_cache(
            sender.objects.filter(**{owner: instance.pk}).values_list(
                "role_id", flat=True
            )
        )
    elif action.startswith("post_") and pk_set:
        drop_role_cache(pk_set)


m2m_changed.connect(
    _role_scope_changed,
    sender=Role.can_view_clients.through,
    dispatch_uid="role_cache_clients",
)
m2m_changed.connect(
    _role_scope_changed,
    sender=Role.can_view_sites.through,
    dispatch_uid="role_cache_sites",
)


class APIKey(BaseAuditModel):
    name = models.CharField(unique=True, max_length=25)
    # only ever holds a key until save() hashes it
    key = models.CharField(blank=True, max_length=48)
    key_hash = models.CharField(unique=True, null=True, blank=True, max_length=64)
    expiration = models.DateTimeField(blank=True, null=True, default=None)
    user = models.ForeignKey(
        "accounts.User", related_name="api_key", on_delete=models.CASCADE
    )

    def save(self, *args, **kwargs):
        if self.key:
            self.key_hash = hashlib.sha256(self.key.encode()).hexdigest()
            self.key = ""
        super().save(*args, **kwargs)

    @staticmethod
    def serialize(apikey):
        from . import serializers

        return serializers.APIKeyAuditSerializer(apikey).data
