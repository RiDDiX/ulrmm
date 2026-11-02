# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Base class and cache settings shared by the API test modules."""

import uuid
from typing import Any, Optional

from django.test import TestCase
from django.test.utils import modify_settings, override_settings
from model_bakery import baker
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from accounts.models import User
from agents.models import Agent
from core.models import CoreSettings
from ulrmm.constants import CustomFieldModel, CustomFieldType
from ulrmm.helpers import make_random_password

# no-op cache: every lookup misses, so cached settings never leak between tests
TEST_CACHE = {"default": {"BACKEND": "ulrmm.cache.ULRMMDummyCache"}}

# for tests that need add/incr/expiry, which the no-op cache cannot do
LOCMEM_CACHE = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "totp-enrolment",
    }
}

# dummy key: a CoreSettings row without one makes the mesh helpers wait for a token
TEST_MESH_KEY = (
    "a767c788bb7045eca9188845404f803c5ec2d68f6ae866781e33fc92ca7126232c470a56"
    "0101340c8c016f6febd3423af9483e5ea47171e89e32a5f02e6365c3a8f0c80f4d2c20b0"
    "db70eb7f16c5930e"
)


def _random_secret() -> str:
    return make_random_password(len=60)


# admin, flash messages and the profiler are not part of the API under test
UNUSED_APPS = ["django.contrib.admin", "django.contrib.messages"]
UNUSED_APPS += ["django_extensions", "silk"]
UNUSED_MIDDLEWARE = [
    "silk.middleware.SilkyMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]


@override_settings(CACHES=TEST_CACHE, DEBUG=False, ADMIN_ENABLED=False)
@modify_settings(
    INSTALLED_APPS={"remove": UNUSED_APPS},
    MIDDLEWARE={"remove": UNUSED_MIDDLEWARE},
)
class ULRMMTestCase(TestCase):
    client: APIClient

    # accounts

    def _account(self, username: str, password: str, **flags: Any) -> User:
        user = User(username=username, **flags)
        user.set_password(password)
        user.save()
        return user

    def authenticate(self) -> None:
        """Log in as the superuser john; alice is a second superuser."""
        self.john = self._account("john", "hunter2", is_superuser=True)
        self.alice = self._account("alice", "hunter2", is_superuser=True)
        self.setup_client()
        self.client.force_authenticate(user=self.john)
        # a real server always has its installer account
        self._account(uuid.uuid4().hex, _random_secret(), is_installer_user=True)

    def setup_client(self) -> None:
        self.client = APIClient()

    def authenticate_agent(self, agent: Agent) -> User:
        """Act as the agent's own API user, as the agent binary would."""
        user = self._account(agent.agent_id, _random_secret(), agent=agent)
        self.client.force_authenticate(user=user, token=Token.objects.create(user=user))
        return user

    def create_user_with_roles(self, roles: list[str]) -> User:
        """Active user whose fresh role has exactly the given flags set."""
        role = baker.make("accounts.Role", **dict.fromkeys(roles, True))
        return baker.make("accounts.User", role=role, is_active=True)

    # fixtures

    def setup_coresettings(self) -> None:
        with override_settings(MESH_TOKEN_KEY=TEST_MESH_KEY):
            self.coresettings = CoreSettings.objects.create()

    def setup_base_instance(self) -> None:
        """Two clients; site1 and site2 belong to company1, site3 to company2."""
        self.company1, self.company2 = baker.make("clients.Client", _quantity=2)
        self.site1, self.site2 = baker.make(
            "clients.Site", client=self.company1, _quantity=2
        )
        self.site3 = baker.make("clients.Site", client=self.company2)
        # one text field per model: client_customfield, site_customfield, ...
        for model in ("client", "site", "agent"):
            field = baker.make(
                "core.CustomField",
                model=CustomFieldModel(model),
                type=CustomFieldType.TEXT,
                name=f"{model}CustomField",
            )
            setattr(self, f"{model}_customfield", field)

    # permission assertions; a KeyError means the view got past the
    # permission check and then failed on the empty test payload

    def _send(self, method: str, url: str, data: Optional[dict]) -> Any:
        return getattr(self.client, method)(
            url, {} if data is None else data, format="json"
        )

    def check_not_authenticated(self, method: str, url: str) -> None:
        self.client.logout()
        self.assertEqual(getattr(self.client, method)(url).status_code, 401)

    def check_not_authorized(
        self, method: str, url: str, data: Optional[dict] = None
    ) -> None:
        try:
            self.assertEqual(self._send(method, url, data).status_code, 403)
        except KeyError:
            pass

    def check_authorized(
        self, method: str, url: str, data: Optional[dict] = None
    ) -> Any:
        try:
            response = self._send(method, url, data)
        except KeyError:
            return None
        self.assertNotEqual(response.status_code, 403)
        return response

    def check_authorized_superuser(
        self, method: str, url: str, data: Optional[dict] = None
    ) -> Any:
        """Both kinds of superuser pass: the Django flag and the role flag."""
        makers = (
            lambda: baker.make("accounts.User", is_active=True, is_superuser=True),
            lambda: self.create_user_with_roles(["is_superuser"]),
        )
        try:
            for make_user in makers:
                self.client.force_authenticate(user=make_user())
                response = self._send(method, url, data)
                self.assertNotEqual(response.status_code, 403)
        except KeyError:
            return None
        self.client.logout()
        return response
