# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.conf import settings
from django.urls import include, path

from . import maint_views, views

PK = "<int:pk>/"


def _crud(view_list, view_item):
    return include([path("", view_list.as_view()), path(PK, view_item.as_view())])


urlpatterns = [
    path("settings/", views.GetEditCoreSettings.as_view()),
    path("branding/", views.PublicBranding.as_view()),
    path("branding/edit/", views.EditBranding.as_view()),
    path("version/", views.version),
    path("health/", views.health),
    path("about/", views.about_info),
    path("emailtest/", views.email_test),
    path("dashinfo/", views.dashboard_info),
    path("stats/", views.FleetStats.as_view()),
    path("servermaintenance/", views.server_maintenance),
    path(
        "customfields/",
        _crud(views.GetAddCustomFields, views.GetUpdateDeleteCustomFields),
    ),
    path("keystore/", _crud(views.GetAddKeyStore, views.UpdateDeleteKeyStore)),
    path("urlaction/", _crud(views.GetAddURLAction, views.UpdateDeleteURLAction)),
    path("schedules/", _crud(views.GetAddSchedule, views.UpdateDeleteSchedule)),
    path(
        "urlaction/run/",
        include(
            [
                path("", views.RunURLAction.as_view()),
                path("test/", views.RunTestURLAction.as_view()),
            ]
        ),
    ),
    path("smstest/", views.TwilioSMSTest.as_view()),
    path("clearcache/", views.clear_cache),
    path("ai/generate/", views.ScriptDraftView.as_view()),
    path("webtermperms/", views.webterm_perms),
    path("status/", views.status),
    path("v2/status/", views.status_v2),
    path("server/update/", maint_views.ServerUpdate.as_view()),
    path("server/update/sources/", maint_views.ServerUpdateSources.as_view()),
    path("server/update/repos/", maint_views.ServerUpdateRepos.as_view()),
    path("server/update/repos/<int:pk>/", maint_views.ServerUpdateRepo.as_view()),
    path("server/update/progress/", maint_views.ServerUpdateProgress.as_view()),
    path("server/tasks/<str:action>/log/", maint_views.ServerTaskLog.as_view()),
    path("server/backups/", maint_views.ServerBackups.as_view()),
    path("server/backups/settings/", maint_views.ServerBackupSettings.as_view()),
    path(
        "server/backups/<str:kind>/<str:name>/",
        maint_views.ServerBackupFile.as_view(),
    ),
]

if not getattr(settings, "HOSTED", False) and not getattr(
    settings, "ULRMM_DISABLE_SERVER_SCRIPTS", False
):
    urlpatterns.append(path("serverscript/test/", views.TestRunServerScript.as_view()))
