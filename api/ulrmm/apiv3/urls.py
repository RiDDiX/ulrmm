# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from deploy.integrity import Integrity

from . import views

# server-wide endpoints, no agent in the path
GLOBAL = {
    "checkrunner": views.CheckRunner,
    "meshexe": views.MeshExe,
    "newagent": views.NewAgent,
    "software": views.Software,
    "installer": views.Installer,
    "natsauth": views.NatsAuth,
    "pins": views.Pins,
    "integrity": Integrity,
    "checkin": views.CheckIn,
    "syncmesh": views.SyncMeshNodeID,
    "choco": views.Choco,
    "winupdates": views.WinUpdates,
    "superseded": views.SupersededWinUpdate,
}

# routes under <str:agentid>/
PER_AGENT = {
    "checkrunner": views.CheckRunner,
    "runchecks": views.RunChecks,
    "checkinterval": views.CheckRunnerInterval,
    "state": views.State,
    "drivers": views.Drivers,
    "security-event": views.SecurityEventReport,
    "cert": views.AgentCert,
    "identity": views.AgentIdentityView,
    "token/challenge": views.TokenChallenge,
    "token/grant": views.TokenGrant,
    "token/refresh": views.TokenRefresh,
    "recover/challenge": views.RecoverChallenge,
    "recover": views.Recover,
    "config": views.AgentConfig,
    "meshreinstall": views.MeshReinstall,
    "selfheal": views.SelfHeal,
}

# routes under <int:pk>/<str:agentid>/
PER_ITEM = {
    "taskrunner": views.TaskRunner,
    "histresult": views.AgentHistoryResult,
}

urlpatterns = (
    [path(f"{route}/", view.as_view()) for route, view in GLOBAL.items()]
    + [
        path(f"<str:agentid>/{route}/", view.as_view())
        for route, view in PER_AGENT.items()
    ]
    + [
        path(f"<int:pk>/<str:agentid>/{route}/", view.as_view())
        for route, view in PER_ITEM.items()
    ]
)
