# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from assets.views import WarrantyLookup
from autotasks.views import GetAddAutoTasks
from checks.views import GetAddChecks
from logs.views import PendingActions

from . import views

_collection_routes = (
    ("", views.GetAgents.as_view()),
    ("history/", views.AgentHistoryView.as_view()),
    ("notes/", views.GetAddNotes.as_view()),
    ("notes/<int:pk>/", views.GetEditDeleteNote.as_view()),
    ("maintenance/bulk/", views.agent_maintenance),
    ("actions/bulk/", views.bulk),
    ("versions/", views.get_agent_versions),
    ("update/", views.update_agents),
    ("update/force/", views.force_update_agents),
    ("installer/", views.install_agent),
    ("bulkrecovery/", views.bulk_agent_recovery),
    ("scripthistory/", views.ScriptRunHistory.as_view()),
)

# Relative to "<agent:agent_id>/". Order matters: Django resolves top down.
_per_agent_routes = (
    ("", views.GetUpdateDeleteAgent.as_view()),
    ("cmd/", views.send_raw_cmd),
    ("runscript/", views.run_script),
    ("wmi/", views.WMI.as_view()),
    ("recover/", views.recover),
    ("reboot/", views.Reboot.as_view()),
    ("shutdown/", views.Shutdown.as_view()),
    ("suspend/", views.Suspend.as_view()),
    ("keepawake/", views.KeepAwake.as_view()),
    ("ping/", views.ping),
    ("perf/", views.perf),
    ("uninstall_code/", views.RevealUninstallCode.as_view()),
    ("warranty/", WarrantyLookup.as_view()),
    ("checks/", GetAddChecks.as_view()),
    ("tasks/", GetAddAutoTasks.as_view()),
    ("pendingactions/", PendingActions.as_view()),
    ("meshcentral/", views.AgentMeshCentral.as_view()),
    ("meshcentral/recover/", views.AgentMeshCentral.as_view()),
    ("meshcentral/console/", views.AgentMeshConsole.as_view()),
    ("<str:port>/webvnc/", views.WebVNC.as_view()),
    ("processes/", views.AgentProcesses.as_view()),
    ("processes/<int:pid>/", views.AgentProcesses.as_view()),
    ("eventlog/<str:logtype>/<int:days>/", views.get_event_log),
    ("history/", views.AgentHistoryView.as_view()),
    # notes are added through notes/, this path only lists them
    (
        "notes/",
        views.GetAddNotes.as_view(http_method_names=["get", "head", "options"]),
    ),
    ("wol/", views.wol),
)

# registry/<verb>-<noun>/ maps to views.<verb>_registry_<noun>, same route name
_registry_ops = (
    ("create", "key"),
    ("delete", "key"),
    ("rename", "key"),
    ("create", "value"),
    ("delete", "value"),
    ("rename", "value"),
    ("modify", "value"),
)

# Literal segments below are all shorter than the 21 characters the <agent>
# converter needs, so they never collide with an agent id.
urlpatterns = [path(route, view) for route, view in _collection_routes]
urlpatterns += [
    path(f"<agent:agent_id>/{route}", view) for route, view in _per_agent_routes
]
urlpatterns.append(
    path("<agent:agent_id>/registry/", views.browse_registry, name="browse_registry")
)
for _verb, _noun in _registry_ops:
    _name = f"{_verb}_registry_{_noun}"
    urlpatterns.append(
        path(
            f"<agent:agent_id>/registry/{_verb}-{_noun}/",
            getattr(views, _name),
            name=_name,
        )
    )
urlpatterns.append(
    path("<agent:agent_id>/terminal-defaults/", views.AgentTerminalDefaults.as_view())
)
