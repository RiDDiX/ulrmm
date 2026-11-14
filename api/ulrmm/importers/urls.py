# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("sources/", views.Sources.as_view()),
    path("sources/<int:pk>/", views.SourceDetail.as_view()),
    path("sources/<int:pk>/fetch/", views.Fetch.as_view()),
    path("sources/<int:pk>/plan/", views.Plan.as_view()),
    path("sources/<int:pk>/import/", views.Import.as_view()),
    path("sources/<int:pk>/devices/", views.Devices.as_view()),
    path("sources/<int:pk>/link/", views.Link.as_view()),
    path("sources/<int:pk>/migrate/", views.Migrate.as_view()),
    path("sources/<int:pk>/remove/", views.Remove.as_view()),
    path("sources/<int:pk>/withdraw/", views.Withdraw.as_view()),
]
