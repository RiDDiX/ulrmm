# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("clients/<int:key>/", views.ScopeItems.as_view(), {"scope": "client"}),
    path("sites/<int:key>/", views.ScopeItems.as_view(), {"scope": "site"}),
    path("agents/<str:key>/", views.ScopeItems.as_view(), {"scope": "agent"}),
    path("documents/", views.AddDocument.as_view()),
    path("documents/<int:pk>/", views.EditDeleteDocument.as_view()),
    path("credentials/", views.AddCredential.as_view()),
    path("credentials/<int:pk>/", views.EditDeleteCredential.as_view()),
    path("credentials/<int:pk>/reveal/", views.RevealCredential.as_view()),
]
