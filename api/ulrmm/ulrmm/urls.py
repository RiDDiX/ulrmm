# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.conf import settings
from django.urls import include, path, register_converter
from django.urls.converters import StringConverter
from knox import views as knox_views

from accounts.views import CheckCredsV2, LoginViewV2
from agents.consumers import CommandStreamConsumer, TerminalStreamConsumer
from core.consumers import DashInfo, TerminalConsumer
from core.views import home
from sso.urls import browser_urlpatterns as sso_browser_urls
from ulrmm.auth import DashboardTokenAuthentication


class AgentIDConverter(StringConverter):
    # agent ids are long random strings; shorter segments fall through
    regex = "[^/]{21,}"


register_converter(AgentIDConverter, "agent")

_APP_ROUTES = (
    ("clients/", "clients.urls"),
    ("deploy/", "deploy.urls"),
    ("agents/", "agents.urls"),
    ("checks/", "checks.urls"),
    ("services/", "services.urls"),
    ("winupdate/", "winupdate.urls"),
    ("patches/", "patches.urls"),
    ("netmon/", "netmon.urls"),
    ("metrics/", "metrics.urls"),
    ("groups/", "groups.urls"),
    ("timeline/", "timeline.urls"),
    ("discovery/", "discovery.urls"),
    ("vulns/", "vulns.urls"),
    ("vault/", "vault.urls"),
    ("encryption/", "encryption.urls"),
    ("nix/", "nix.urls"),
    ("dashboard/", "dashboard.urls"),
    ("laps/", "laps.urls"),
    ("integrations/", "integrations.urls"),
    ("importers/", "importers.urls"),
    ("notify/", "notify.urls"),
    ("lifecycle/", "assets.urls"),
    ("packages/", "packages.urls"),
    ("appupdates/", "appupdates.urls"),
    ("software/", "software.urls"),
    ("core/", "core.urls"),
    ("automation/", "automation.urls"),
    ("tasks/", "autotasks.urls"),
    ("logs/", "logs.urls"),
    ("scripts/", "scripts.urls"),
    ("alerts/", "alerts.urls"),
    ("accounts/", "accounts.urls"),
    ("", "remote.urls"),
    ("api/v3/", "apiv3.urls"),
    ("api/v4/", "apiv4.urls"),
    ("reporting/", "reporting.urls"),
)

_dash_auth = (DashboardTokenAuthentication,)

urlpatterns = [
    path("", home),
    path("v2/checkcreds/", CheckCredsV2.as_view()),
    path("v2/login/", LoginViewV2.as_view()),
    path("logout/", knox_views.LogoutView.as_view(authentication_classes=_dash_auth)),
    path(
        "logoutall/",
        knox_views.LogoutAllView.as_view(authentication_classes=_dash_auth),
    ),
]
urlpatterns += [path(prefix, include(module)) for prefix, module in _APP_ROUTES]

if not getattr(settings, "ULRMM_DISABLE_SSO", False):
    urlpatterns += (
        path("_allauth/", include(sso_browser_urls)),
        path("accounts/", include("sso.urls")),
    )

if getattr(settings, "ADMIN_ENABLED", False):
    from django.contrib import admin

    urlpatterns += (path(settings.ADMIN_URL, admin.site.urls),)

if getattr(settings, "DEBUG", False):
    urlpatterns.append(path("silk/", include("silk.urls", namespace="silk")))

if getattr(settings, "SWAGGER_ENABLED", False):
    from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

    urlpatterns.append(path("api/schema/", SpectacularAPIView.as_view(), name="schema"))
    urlpatterns.append(
        path(
            "api/schema/swagger-ui/",
            SpectacularSwaggerView.as_view(url_name="schema"),
            name="swagger-ui",
        )
    )

_web_terminal = not getattr(settings, "HOSTED", False) and not getattr(
    settings, "ULRMM_DISABLE_WEB_TERMINAL", False
)

ws_urlpatterns = [path("ws/dashinfo/", DashInfo.as_asgi())]
ws_urlpatterns.append(
    path("ws/agent/<str:agent_id>/cmd/", CommandStreamConsumer.as_asgi())
)
ws_urlpatterns.append(
    path(
        "ws/agent/<str:agent_id>/terminal/<str:session_id>/",
        TerminalStreamConsumer.as_asgi(),
    )
)
if _web_terminal:
    ws_urlpatterns.append(path("ws/rmmcli/", TerminalConsumer.as_asgi()))
