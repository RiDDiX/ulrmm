# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from .views import GetAuditLogs, GetDebugLog, PendingActions, pending_count

urlpatterns = [
    path("debug/", GetDebugLog.as_view()),
    path("audit/", GetAuditLogs.as_view()),
    path("pendingactions/<int:pk>/", PendingActions.as_view()),
    path("pendingactions/", PendingActions.as_view()),
    path("pendingactions/count/", pending_count),
]
