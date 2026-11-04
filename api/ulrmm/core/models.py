# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import smtplib
import ssl
from contextlib import suppress
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formatdate

from cryptography.fernet import InvalidToken
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from twilio.rest import Client as TwClient

from logs.models import BaseAuditModel, hmac_marker
from ulrmm.constants import (
    ALL_TIMEZONES,
    CORE_SETTINGS_SECRET_FIELDS,
    CORESETTINGS_CACHE_KEY,
    CustomFieldModel,
    CustomFieldType,
    DarwinTerminalShellChoices,
    DebugLogLevel,
    FreeBSDTerminalShellChoices,
    LinuxTerminalShellChoices,
    MonthlyType,
    ScheduleType,
    TerminalModeChoices,
    URLActionRestMethod,
    URLActionType,
    WindowsTerminalShellChoices,
)

# HKDF "info" strings pin each ciphertext to its column; they must never change
# or the stored tokens could no longer be decrypted.
NVD_KEY_INFO = b"core.CoreSettings.nvd_api_key"
DELL_API_INFO = {
    "dell_api_client_id": b"core.CoreSettings.dell_api_client_id",
    "dell_api_client_secret": b"core.CoreSettings.dell_api_client_secret",
}
SECRET_FIELD_INFO = {
    field: f"core.CoreSettings.{field}".encode()
    for field in CORE_SETTINGS_SECRET_FIELDS
}
# renamed from open_ai_token, its tokens keep the old info string
SECRET_FIELD_INFO["ai_api_key"] = b"core.CoreSettings.open_ai_token"

KEYSTORE_VALUE_INFO = b"core.GlobalKVStore.value"
URLACTION_BODY_INFO = b"core.URLAction.rest_body"
URLACTION_HEADERS_INFO = b"core.URLAction.rest_headers"
RELEASE_REPO_TOKEN_INFO = b"core.ReleaseRepo.token"

TZ_CHOICES = [(name, name) for name in ALL_TIMEZONES]


def _encrypt(value: str, info: bytes) -> str:
    from remote.utils import encrypt_secret

    return encrypt_secret(value, info)


def _decrypt(token: str, info: bytes) -> str:
    from remote.utils import decrypt_secret

    return decrypt_secret(token, info)


FERNET_PREFIX = "gAAAAA"
SMS_TIMEOUT = 15
_UNREADABLE_LOGGED = set()


class EncryptedTextField(models.TextField):
    """TextField whose column holds a Fernet token while the in-memory value
    stays plaintext. Only the stored form changes, so callers read the field
    unchanged. Legacy plaintext rows (before the data migration) read back as
    themselves until the next save re-stores them encrypted.
    """

    def __init__(self, *args, hkdf_info=None, unreadable="", **kwargs):
        self.hkdf_info = hkdf_info
        # what a token no configured key opens reads as
        self.unreadable = unreadable
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        kwargs["hkdf_info"] = self.hkdf_info
        if self.unreadable:
            kwargs["unreadable"] = self.unreadable
        return name, path, args, kwargs

    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return _decrypt(value, self.hkdf_info)
        except InvalidToken:
            if value.startswith(FERNET_PREFIX):
                # a token from another key is no credential: report it once
                # and read it as the field's unreadable value, never wrapped
                label = f"{self.model._meta.label}.{self.name}"
                if label not in _UNREADABLE_LOGGED:
                    from ulrmm.logger import logger

                    _UNREADABLE_LOGGED.add(label)
                    logger.critical(
                        "%s cannot be decrypted with FIELD_ENCRYPTION_KEYS or "
                        "SECRET_KEY; enter it again",
                        label,
                    )
                return self.unreadable
            return value

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if not value:
            return value
        try:
            # an already-encrypted value is stored as is
            _decrypt(value, self.hkdf_info)
            return value
        except InvalidToken:
            return _encrypt(value, self.hkdf_info)


def recrypt_column(connection, model, field: str, info: bytes, *, plain: bool):
    """Stores every value of the column again under the current key, raw, past
    the field's own conversion. ``plain``: values that are no token are
    plaintext to encrypt (EncryptedTextField), else they are left alone.
    A row changed since it was read keeps the newer value.
    Returns (rewritten, unreadable, skipped)."""
    from remote.utils import encrypt_secret, rotate_secret

    table = connection.ops.quote_name(model._meta.db_table)
    column = connection.ops.quote_name(model._meta.get_field(field).column)
    pk = connection.ops.quote_name(model._meta.pk.column)
    rewritten = unreadable = skipped = 0
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {pk}, {column} FROM {table} WHERE {column} <> ''")
        rows = cursor.fetchall()
        for key, value in rows:
            try:
                new = rotate_secret(value, info)
            except InvalidToken:
                if value.startswith(FERNET_PREFIX) or not plain:
                    unreadable += value.startswith(FERNET_PREFIX)
                    continue
                new = encrypt_secret(value, info)
            cursor.execute(
                f"UPDATE {table} SET {column} = %s WHERE {pk} = %s AND {column} = %s",
                [new, key, value],
            )
            if cursor.rowcount:
                rewritten += 1
            else:
                skipped += 1
    return rewritten, unreadable, skipped


def decrypt_column(connection, model, field: str, info: bytes, unreadable=None) -> None:
    """Back to plaintext, for migrating a column back. A token no key opens
    stays, or becomes ``unreadable`` when given."""
    from remote.utils import decrypt_secret

    table = connection.ops.quote_name(model._meta.db_table)
    column = connection.ops.quote_name(model._meta.get_field(field).column)
    pk = connection.ops.quote_name(model._meta.pk.column)
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {pk}, {column} FROM {table} WHERE {column} <> ''")
        for key, value in cursor.fetchall():
            try:
                plain = decrypt_secret(value, info)
            except InvalidToken:
                if unreadable is None or not value.startswith(FERNET_PREFIX):
                    continue
                plain = unreadable
            cursor.execute(
                f"UPDATE {table} SET {column} = %s WHERE {pk} = %s", [plain, key]
            )


def _server_feature_allowed(disable_setting: str) -> bool:
    if getattr(settings, "HOSTED", False):
        return False
    return not getattr(settings, disable_setting, False)


class CoreSettings(BaseAuditModel):
    email_alert_recipients = ArrayField(
        models.EmailField(null=True, blank=True),
        blank=True,
        default=list,
    )
    sms_alert_recipients = ArrayField(
        models.CharField(max_length=255, null=True, blank=True),
        blank=True,
        default=list,
    )
    twilio_number = models.CharField(max_length=255, null=True, blank=True)
    twilio_account_sid = models.CharField(max_length=255, null=True, blank=True)
    twilio_auth_token = EncryptedTextField(
        null=True, blank=True, hkdf_info=SECRET_FIELD_INFO["twilio_auth_token"]
    )
    smtp_from_email = models.CharField(
        blank=True, max_length=255, default="from@example.com"
    )
    smtp_from_name = models.CharField(null=True, blank=True, max_length=255)
    smtp_host = models.CharField(blank=True, max_length=255, default="smtp.gmail.com")
    smtp_host_user = models.CharField(
        blank=True, max_length=255, default="admin@example.com"
    )
    smtp_host_password = EncryptedTextField(
        blank=True,
        default="changeme",
        hkdf_info=SECRET_FIELD_INFO["smtp_host_password"],
    )
    smtp_port = models.PositiveIntegerField(blank=True, default=587)
    smtp_requires_auth = models.BooleanField(default=True)
    default_time_zone = models.CharField(
        max_length=255, choices=TZ_CHOICES, default="America/Los_Angeles"
    )
    check_history_prune_days = models.PositiveIntegerField(default=30)
    metric_history_days = models.PositiveIntegerField(
        default=30, validators=[MinValueValidator(1), MaxValueValidator(365)]
    )
    resolved_alerts_prune_days = models.PositiveIntegerField(default=0)
    agent_history_prune_days = models.PositiveIntegerField(default=60)
    debug_log_prune_days = models.PositiveIntegerField(default=30)
    audit_log_prune_days = models.PositiveIntegerField(default=0)
    patch_event_prune_days = models.PositiveIntegerField(default=0)
    report_history_prune_days = models.PositiveIntegerField(default=0)
    agent_debug_level = models.CharField(
        max_length=20, choices=DebugLogLevel.choices, default=DebugLogLevel.INFO
    )
    clear_faults_days = models.IntegerField(default=0)
    mesh_token = EncryptedTextField(
        null=True, blank=True, default="", hkdf_info=SECRET_FIELD_INFO["mesh_token"]
    )
    mesh_username = models.CharField(null=True, blank=True, max_length=255, default="")
    mesh_site = models.CharField(null=True, blank=True, max_length=255, default="")
    mesh_device_group = models.CharField(
        null=True, blank=True, max_length=255, default="UniversalLocalRMM"
    )
    mesh_company_name = models.CharField(null=True, blank=True, max_length=255)
    sync_mesh_with_rmm = models.BooleanField(default=True)
    agent_auto_update = models.BooleanField(default=True)
    workstation_policy = models.ForeignKey(
        "automation.Policy",
        null=True,
        blank=True,
        related_name="default_workstation_policy",
        on_delete=models.SET_NULL,
    )
    server_policy = models.ForeignKey(
        "automation.Policy",
        null=True,
        blank=True,
        related_name="default_server_policy",
        on_delete=models.SET_NULL,
    )
    alert_template = models.ForeignKey(
        "alerts.AlertTemplate",
        null=True,
        blank=True,
        related_name="default_alert_template",
        on_delete=models.SET_NULL,
    )
    date_format = models.CharField(
        blank=True, max_length=30, default="MMM-DD-YYYY - HH:mm"
    )
    ai_api_key = EncryptedTextField(
        null=True, blank=True, hkdf_info=SECRET_FIELD_INFO["ai_api_key"]
    )
    nvd_api_key = models.TextField(blank=True, default="")
    ai_model = models.CharField(blank=True, max_length=255, default="gpt-3.5-turbo")
    enable_server_scripts = models.BooleanField(default=False)
    enable_server_webterminal = models.BooleanField(default=False)
    notify_on_info_alerts = models.BooleanField(default=False)
    notify_on_warning_alerts = models.BooleanField(default=True)
    block_local_user_logon = models.BooleanField(default=False)
    sso_enabled = models.BooleanField(default=False)
    default_shell_windows = models.CharField(
        max_length=32,
        choices=WindowsTerminalShellChoices.choices,
        default=WindowsTerminalShellChoices.CMD,
    )
    default_shell_windows_custom = models.CharField(
        blank=True, max_length=512, default=""
    )
    default_shell_linux = models.CharField(
        max_length=32,
        choices=LinuxTerminalShellChoices.choices,
        default=LinuxTerminalShellChoices.BASH,
    )
    default_shell_linux_custom = models.CharField(
        blank=True, max_length=512, default=""
    )
    default_shell_darwin = models.CharField(
        max_length=32,
        choices=DarwinTerminalShellChoices.choices,
        default=DarwinTerminalShellChoices.BASH,
    )
    default_shell_darwin_custom = models.CharField(
        blank=True, max_length=512, default=""
    )
    default_shell_freebsd = models.CharField(
        max_length=32,
        choices=FreeBSDTerminalShellChoices.choices,
        default=FreeBSDTerminalShellChoices.SH,
    )
    default_shell_freebsd_custom = models.CharField(
        blank=True, max_length=512, default=""
    )
    terminal_mode = models.CharField(
        max_length=20,
        choices=TerminalModeChoices.choices,
        default=TerminalModeChoices.NEW,
    )
    dell_api_client_id = models.TextField(blank=True, default="")
    dell_api_client_secret = models.TextField(blank=True, default="")
    tamper_watch = models.BooleanField(default=False)
    tamper_offline_minutes = models.PositiveIntegerField(
        default=15, validators=[MinValueValidator(5), MaxValueValidator(1440)]
    )

    def __str__(self) -> str:
        return "Global Site Settings"

    # the cached copy leaves the secrets out; reading one on a cached object
    # loads that column from the database (deferred field) and decrypts it
    def __getstate__(self):
        state = super().__getstate__()
        for field in SECRET_FIELD_INFO:
            state.pop(field, None)
        return state

    def save(self, *args, **kwargs) -> None:
        cache.delete(CORESETTINGS_CACHE_KEY)

        if not self.pk and CoreSettings.objects.exists():
            raise ValidationError("There can only be one CoreSettings instance")

        if self._state.adding:
            # install.sh / initial_db_setup seed Mesh credentials from settings
            seeds = (
                ("mesh_site", lambda: settings.MESH_SITE),
                ("mesh_username", lambda: settings.MESH_USERNAME.lower()),
                ("mesh_token", lambda: settings.MESH_TOKEN_KEY),
            )
            for attr, read in seeds:
                with suppress(Exception):
                    setattr(self, attr, read())

        old_settings = None
        if self.pk:
            old_settings = CoreSettings.objects.filter(pk=self.pk).first()
            # never lock every user out of the dashboard
            if not self.sso_enabled and self.block_local_user_logon:
                self.block_local_user_logon = False

        super().save(*args, **kwargs)
        cache.delete(CORESETTINGS_CACHE_KEY)

        if not old_settings:
            return
        moved = {
            fk
            for fk in ("alert_template_id", "server_policy_id", "workstation_policy_id")
            if getattr(old_settings, fk) != getattr(self, fk)
        }
        if not moved:
            return

        from alerts.tasks import cache_agents_alert_template

        cache_agents_alert_template.delay()
        if moved - {"alert_template_id"}:
            cache.delete_many_pattern("agent_*")

    @property
    def mesh_api_superuser(self) -> str:
        # must be lowercase or the mesh api rejects it
        return self.mesh_username.lower()

    @property
    def sms_is_configured(self) -> bool:
        return bool(
            self.twilio_auth_token and self.twilio_account_sid and self.twilio_number
        )

    @property
    def email_is_configured(self) -> bool:
        needed = [self.smtp_from_email, self.smtp_host, self.smtp_port]
        if self.smtp_requires_auth:
            needed += [self.smtp_host_user, self.smtp_host_password]
        return all(needed)

    @property
    def server_scripts_enabled(self) -> bool:
        return self.enable_server_scripts and _server_feature_allowed(
            "ULRMM_DISABLE_SERVER_SCRIPTS"
        )

    @property
    def web_terminal_enabled(self) -> bool:
        return self.enable_server_webterminal and _server_feature_allowed(
            "ULRMM_DISABLE_WEB_TERMINAL"
        )

    def send_mail(
        self,
        subject,
        body,
        attachment=None,
        attachment_filename=None,
        attachment_type=None,
        attachment_extension=None,
        alert_template=None,
        override_recipients=[],
        test=False,
    ):
        from ulrmm.logger import logger

        from logs.models import DebugLog

        if not self.email_is_configured:
            if test:
                return (
                    "There needs to be at least one email recipient configured",
                    False,
                )
            return ("SMTP messaging not configured.", False)

        from_address = (
            alert_template.email_from
            if alert_template and alert_template.email_from
            else self.smtp_from_email
        )

        if override_recipients:
            recipients = override_recipients
        elif alert_template and alert_template.email_recipients:
            recipients = alert_template.email_recipients
        elif self.email_alert_recipients:
            recipients = self.email_alert_recipients
        else:
            return (
                "There needs to be at least one email recipient configured",
                False,
            )

        attach_kinds = {
            "pdf": ({"maintype": "application", "subtype": "pdf"}, "pdf"),
            "html": ({"subtype": "html"}, "html"),
            "plaintext": ({"subtype": "plain"}, attachment_extension or "txt"),
        }
        implicit_tls = self.smtp_port == 465
        auth = self.smtp_requires_auth
        if auth:
            upgrade = not implicit_tls
        else:
            # Google's relay refuses plain text sessions
            upgrade = self.smtp_host == "smtp-relay.gmail.com"

        try:
            msg = EmailMessage()
            sender = (
                Address(display_name=self.smtp_from_name, addr_spec=from_address)
                if self.smtp_from_name
                else from_address
            )
            headers = (
                ("Subject", subject),
                ("Date", formatdate(localtime=True)),
                ("From", sender),
                ("To", ", ".join(recipients)),
            )
            for name, value in headers:
                msg[name] = value
            msg.set_content(body)

            if attachment and attachment_type in attach_kinds:
                kind_opts, ext = attach_kinds[attachment_type]
                msg.add_attachment(
                    attachment, filename=f"{attachment_filename}.{ext}", **kind_opts
                )

            if implicit_tls:
                server = smtplib.SMTP_SSL(
                    self.smtp_host,
                    self.smtp_port,
                    timeout=20,
                    context=ssl.create_default_context(),
                )
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=20)

            if auth or upgrade:
                server.ehlo()
            if upgrade:
                server.starttls(context=ssl.create_default_context())
            if auth:
                server.login(self.smtp_host_user, self.smtp_host_password)
            server.send_message(msg)
            server.quit()
        except Exception as e:
            logger.error("sending email failed", exc_info=True)
            DebugLog.error(message=f"Sending email failed with error: {e}")
            return (str(e), False)

        return ("Email test ok!" if test else "ok", True)

    def send_sms(self, body, alert_template=None, test=False):
        from logs.models import DebugLog

        if not self.sms_is_configured:
            return ("Sms alerting is not setup correctly.", False)

        if alert_template and alert_template.text_recipients:
            recipients = alert_template.text_recipients
        elif self.sms_alert_recipients:
            recipients = self.sms_alert_recipients
        else:
            return ("No sms recipients found", False)

        from requests import RequestException
        from twilio.base.exceptions import TwilioException
        from twilio.http.http_client import TwilioHttpClient

        # without a timeout an unreachable Twilio holds the worker
        tw_client = TwClient(
            self.twilio_account_sid,
            self.twilio_auth_token,
            http_client=TwilioHttpClient(timeout=SMS_TIMEOUT),
        )
        for num in recipients:
            try:
                tw_client.messages.create(body=body, to=num, from_=self.twilio_number)
            except TwilioException as e:
                DebugLog.error(message=f"SMS failed to send: {e}")
                return (str(e), False)
            # ValueError: a 2xx that is not JSON, from a proxy or captive portal
            except (RequestException, ValueError) as e:
                DebugLog.error(message=f"SMS failed to send: {e}")
                if not test:
                    # the alert tasks hand their claim back and send again
                    raise
                return (str(e), False)

        return ("SMS Test sent successfully!" if test else "ok", True)

    @staticmethod
    def serialize(core):
        from . import serializers

        return serializers.CoreSerializer(core).data


class CustomField(BaseAuditModel):
    order = models.PositiveIntegerField(default=0)
    model = models.CharField(max_length=25, choices=CustomFieldModel.choices)
    type = models.CharField(
        max_length=25, choices=CustomFieldType.choices, default=CustomFieldType.TEXT
    )
    options = ArrayField(
        models.CharField(max_length=255, null=True, blank=True),
        null=True,
        blank=True,
        default=list,
    )
    name = models.CharField(max_length=100)
    required = models.BooleanField(blank=True, default=False)
    default_value_string = models.TextField(null=True, blank=True)
    default_value_bool = models.BooleanField(default=False)
    default_values_multiple = ArrayField(
        models.CharField(max_length=255, null=True, blank=True),
        null=True,
        blank=True,
        default=list,
    )
    hide_in_ui = models.BooleanField(default=False)
    hide_in_summary = models.BooleanField(default=False)

    class Meta:
        unique_together = (("model", "name"),)

    def __str__(self) -> str:
        return self.name

    @property
    def default_value(self):
        source = {
            CustomFieldType.MULTIPLE: "default_values_multiple",
            CustomFieldType.CHECKBOX: "default_value_bool",
        }.get(self.type, "default_value_string")
        return getattr(self, source)

    def get_or_create_field_value(self, instance):
        from agents.models import Agent, AgentCustomField
        from clients.models import Client, ClientCustomField, Site, SiteCustomField

        owners = (
            (Agent, AgentCustomField, "agent"),
            (Client, ClientCustomField, "client"),
            (Site, SiteCustomField, "site"),
        )
        for owner_cls, value_model, fk in owners:
            if isinstance(instance, owner_cls):
                obj, _ = value_model.objects.get_or_create(field=self, **{fk: instance})
                return obj
        return None

    @staticmethod
    def serialize(field):
        from . import serializers

        return serializers.CustomFieldSerializer(field).data


class ReleaseRepo(models.Model):
    """Release repository besides the built-in GitHub and Gitea sources.
    Same pinned signature as the others."""

    name = models.CharField(max_length=32, unique=True)
    repo_url = models.CharField(max_length=255)
    token = EncryptedTextField(
        hkdf_info=RELEASE_REPO_TOKEN_INFO, blank=True, default=""
    )
    enabled = models.BooleanField(default=True)
    position = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ("position", "id")

    def __str__(self) -> str:
        return self.name


class GlobalKVStore(BaseAuditModel):
    name = models.CharField(max_length=25, unique=True)
    value = EncryptedTextField(hkdf_info=KEYSTORE_VALUE_INFO)

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(store):
        from .serializers import KeyStoreSerializer

        data = KeyStoreSerializer(store).data
        data["value"] = hmac_marker(store.value)
        return data


class URLAction(BaseAuditModel):
    name = models.CharField(max_length=255)
    desc = models.TextField(null=True, blank=True)
    pattern = models.TextField()
    action_type = models.CharField(
        max_length=10, choices=URLActionType.choices, default=URLActionType.WEB
    )
    rest_method = models.CharField(
        max_length=10,
        choices=URLActionRestMethod.choices,
        default=URLActionRestMethod.POST,
    )
    rest_body = EncryptedTextField(
        null=True, blank=True, default="", hkdf_info=URLACTION_BODY_INFO
    )
    rest_headers = EncryptedTextField(
        null=True, blank=True, default="", hkdf_info=URLACTION_HEADERS_INFO
    )

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(action):
        from .serializers import URLActionSerializer

        data = URLActionSerializer(action).data
        data["rest_body"] = hmac_marker(action.rest_body)
        data["rest_headers"] = hmac_marker(action.rest_headers)
        # webhook urls often carry tokens
        data["pattern"] = hmac_marker(action.pattern)
        return data


class Schedule(BaseAuditModel):
    name = models.CharField(max_length=255)
    run_time = models.TimeField()
    run_time_weekdays = ArrayField(
        models.PositiveSmallIntegerField(), null=True, blank=True, default=list, size=7
    )
    monthly_months_of_year = ArrayField(
        models.PositiveSmallIntegerField(),
        null=True,
        blank=True,
        default=list,
        size=12,
    )
    monthly_days_of_month = ArrayField(
        models.PositiveIntegerField(), null=True, blank=True, default=list, size=32
    )
    monthly_weeks_of_month = ArrayField(
        models.PositiveSmallIntegerField(), null=True, blank=True, default=list, size=6
    )
    schedule_type = models.CharField(
        max_length=15, choices=ScheduleType.choices, default=ScheduleType.WEEKLY
    )
    monthly_type = models.CharField(
        max_length=15, choices=MonthlyType.choices, default=MonthlyType.DAYS
    )

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(schedule):
        from . import serializers

        return serializers.ScheduleAuditSerializer(schedule).data
