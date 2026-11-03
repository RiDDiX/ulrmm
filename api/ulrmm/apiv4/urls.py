# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("<str:agentid>/<int:pk>/chocoresult/", views.ChocoResultV4.as_view()),
    path("<str:agentid>/<int:pk>/wingetresult/", views.WingetResultV4.as_view()),
    path("<str:agentid>/sdio/<str:job>/", views.SdioJobV4.as_view()),
    path("<str:agentid>/pkgjob/<int:job>/", views.PkgJobV4.as_view()),
]
